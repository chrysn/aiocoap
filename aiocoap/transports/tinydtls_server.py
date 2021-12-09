# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a MessageInterface that serves coaps:// using a
wrapped tinydtls library.

Bear in mind that the aiocoap CoAPS support is highly experimental and
incomplete.

Unlike other transports this is *not* enabled automatically in general, as it
is limited to servers bound to a single address for implementation reasons.
(Basically, because it is built on the simplesocketserver rather than the udp6
server -- that can change in future, though). Until either the implementation
is changed or binding arguments are (allowing different transports to bind to
per-transport addresses or ports), a DTLS server will only be enabled if the
AIOCOAP_DTLSSERVER_ENABLED environment variable is set, or tinydtls_server is
listed explicitly in AIOCOAP_SERVER_TRANSPORT.
"""

# Comparing this to the tinydtls transport, things are a bit easier as we don't
# expect to send the first DTLS payload (thus don't need the queue), and don't
# need that clean a cleanup (at least if we assume that the clients all shut
# down on their own anyway).
#
# Then again, keeping connections live for as long as someone holds their
# address (eg. by some "pool with N strong references, and the rest are weak"
# and just go away on overflow unless someone keeps the address alive) would be
# more convenient here.

import asyncio
from collections import OrderedDict

import time

from ..numbers.constants import COAPS_PORT
from .generic_udp import GenericMessageInterface
from .. import error, interfaces
from . import simplesocketserver
from .simplesocketserver import _DatagramServerSocketSimple
from ..util.asyncio import py38args

from .tinydtls import LEVEL_NOALERT, LEVEL_FATAL, DTLS_EVENT_CONNECT, DTLS_EVENT_CONNECTED, CODE_CLOSE_NOTIFY, CloseNotifyReceived, DTLS_TICKS_PER_SECOND, DTLS_CLOCK_OFFSET, FatalDTLSError

# tinyDTLS passes address information around in its session data, but the way
# it's used here that will be ignored; this is the data that is sent to / read
# from the tinyDTLS functions
_SENTINEL_ADDRESS = "::1"
_SENTINEL_PORT = 1234

# While we don't have retransmissions set up, this helps work issues of dropped
# packets from sending in rapid succession
_SEND_SLEEP_WORKAROUND = 0

class _AddressDTLS(interfaces.EndpointAddress):
    # no slots here, thus no equality other than identity, which is good

    def __init__(self, protocol, underlying_address):
        from DTLSSocket import dtls

        self._protocol = protocol
        self._underlying_address = simplesocketserver._Address(protocol, underlying_address)

        self._dtls_socket = None

        self._psk_store = SecurityStore(protocol._server_credentials)

        self._dtls_socket = dtls.DTLS(
                # FIXME: Use accessors like tinydtls (but are they needed? maybe shutdown sequence is just already better here...)
                read=self._read,
                write=self._write,
                event=self._event,
                pskId=b"The socket needs something there but we'll never use it",
                pskStore=self._psk_store,
                )
        self._dtls_session = dtls.Session(_SENTINEL_ADDRESS, _SENTINEL_PORT)

        self._retransmission_task = asyncio.create_task(
                self._run_retransmissions(),
                **py38args(name="DTLS server handshake retransmissions")
                )

        self.log = protocol.log

    is_multicast = False
    is_multicast_locally = False
    hostinfo = property(lambda self: self._underlying_address.hostinfo)
    uri_base = property(lambda self: 'coaps://' + self.hostinfo)
    hostinfo_local = property(lambda self: self._underlying_address.hostinfo_local)
    uri_base_local = property(lambda self: 'coaps://' + self.hostinfo_local)

    scheme = 'coaps'

    authenticated_claims = property(lambda self: [self._psk_store._claims])

    @property
    def blockwise_key(self):
        return (self._underlying_address.blockwise_key, self._psk_store._claims)

    # implementing GenericUdp addresses

    def send(self, message):
        self._dtls_socket.write(self._dtls_session, message)

    # dtls callbacks

    def _read(self, sender, data):
        # ignoring sender: it's only _SENTINEL_*
        self._protocol._message_interface._received_plaintext(self, data)

        return len(data)

    def _write(self, recipient, data):
        if _SEND_SLEEP_WORKAROUND and \
                len(data) > 13 and data[0] == 22 and data[13] == 14:
            time.sleep(_SEND_SLEEP_WORKAROUND)
        self._underlying_address.send(data)
        return len(data)

    def _event(self, level, code):
        if (level, code) == (LEVEL_NOALERT, DTLS_EVENT_CONNECT):
            return
        elif (level, code) == (LEVEL_NOALERT, DTLS_EVENT_CONNECTED):
            # No need to react to "connected": We're not the ones sending the first message
            return
        elif (level, code) == (LEVEL_FATAL, CODE_CLOSE_NOTIFY):
            self._inject_error(CloseNotifyReceived())
        elif level == LEVEL_FATAL:
            self._inject_error(FatalDTLSError(code))
        else:
            self.log.warning("Unhandled alert level %d code %d", level, code)

    # own helpers copied and adjusted from tinydtls

    def _inject_error(self, e):
        # this includes "was shut down" with a CloseNotifyReceived e
        """Put an error to all pending operations on this remote, just as if it
        were raised inside the main loop."""
        self._protocol._message_interface._received_exception(self, e)

        self._retransmission_task.cancel()

        self._protocol._connections.pop(self._underlying_address.address)

    # This is a bit more defensive than the one in tinydtls as it starts out in
    # waiting, and RFC6347 indicates on a brief glance that the state machine
    # could go from waiting to some other state later on, so we (re)trigger it
    # whenever something comes in
    async def _run_retransmissions(self):
        when = self._dtls_socket.checkRetransmit() / DTLS_TICKS_PER_SECOND
        if when == 0:
            return
        # FIXME: Find out whether the DTLS server is ever supposed to send
        # retransmissions in the first place (this part was missing an import
        # and it never showed).
        now = time.time() - DTLS_CLOCK_OFFSET
        await asyncio.sleep(when - now)
        self._retransmission_task = asyncio.create_task(
                self._run_retransmissions(),
                **py38args(name="DTLS server handshake retransmissions")
                )

class _DatagramServerSocketSimpleDTLS(_DatagramServerSocketSimple):
    _Address = _AddressDTLS
    max_sockets = 64

    def __init__(self, *args, **kwargs):
        self._connections = OrderedDict() # analogous to simple6's _sockets
        return super().__init__(*args, **kwargs)

    async def connect(self, sockaddr):
        # Even if we opened a connection, it wouldn't have the same security
        # properties as the incoming one that it's probably supposed to replace
        # would have had
        raise RuntimeError("Sending initial messages via a DTLSServer is not supported")

    # Overriding to use GoingThroughMessageDecryption adapter
    @classmethod
    async def create(cls, bind, log, loop, message_interface):
        wrapped_interface = GoingThroughMessageDecryption(message_interface)
        self = await super().create(bind, log, loop, wrapped_interface)
        # self._security_store left uninitialized to ease subclassing from SimpleSocketServer; should be set before using this any further
        return self

    # Overriding as now we do need to manage the pol
    def datagram_received(self, data, sockaddr):
        if sockaddr in self._connections:
            address = self._connections[sockaddr]
            self._connections.move_to_end(sockaddr)
        else:
            address = self._Address(self, sockaddr)
            self._connections[sockaddr] = address
        self._message_interface._received_datagram(address, data)

    def _maybe_purge_sockets(self):
        while len(self._connections) >= self.max_sockets: # more of an if
            oldaddr, oldest = next(iter(self._connections.items()))
            # FIXME custom error?
            oldest._inject_error(error.LibraryShutdown("Connection is being closed for lack of activity"))

class GoingThroughMessageDecryption:
    """Warapper around GenericMessageInterface that puts incoming data through
    the DTLS context stored with the address"""
    def __init__(self, plaintext_interface: "GenericMessageInterface"):
        self._plaintext_interface = plaintext_interface

    def _received_datagram(self, address, data):
        # Put it into the DTLS processor; that'll forward any actually contained decrypted datagrams on to _received_plaintext
        address._retransmission_task.cancel()
        address._dtls_socket.handleMessage(address._dtls_session, data)
        address._retransmission_task = asyncio.create_task(
                address._run_retransmissions(),
                **py38args(name="DTLS server handshake retransmissions")
                )

    def _received_exception(self, address, exception):
        self._plaintext_interface._received_exception(address, exception)

    def _received_plaintext(self, address, data):
        self._plaintext_interface._received_datagram(address, data)

class SecurityStore:
    """Wrapper around a CredentialsMap that makes it accessible to the
    dict-like object DTLSSocket expects.

    Not only does this convert interfaces, it also adds a back channel: As
    DTLSSocket wouldn't otherwise report who authenticated, this is tracking
    access and storing the claims associated with the used key for later use.

    Therefore, SecurityStore objects are created per connection and not per
    security store.
    """

    def __init__(self, server_credentials):
        self._server_credentials = server_credentials

        self._claims = None

    def keys(self):
        return self

    def __contains__(self, key):
        try:
            self._server_credentials.find_dtls_psk(key)
            return True
        except KeyError:
            return False

    def __getitem__(self, key):
        (psk, claims) = self._server_credentials.find_dtls_psk(key)
        if self._claims not in (None, claims):
            # I didn't know it could do that -- how would we know which is the
            # one it eventually picked?
            raise RuntimeError("DTLS stack tried accessing different keys")
        self._claims = claims
        return psk

class MessageInterfaceTinyDTLSServer(simplesocketserver.MessageInterfaceSimpleServer):
    _default_port = COAPS_PORT
    _serversocket = _DatagramServerSocketSimpleDTLS

    @classmethod
    async def create_server(cls, bind, ctx: interfaces.MessageManager, log, loop, server_credentials):
        self = await super().create_server(bind, ctx, log, loop)

        self._pool._server_credentials = server_credentials

        return self

    async def shutdown(self):
        remaining_connections = list(self._pool._connections.values())
        for c in remaining_connections:
            c._inject_error(error.LibraryShutdown("Shutting down"))
        await super().shutdown()
