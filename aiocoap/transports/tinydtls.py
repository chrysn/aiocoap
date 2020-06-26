# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a MessageInterface that handles coaps:// using a
wrapped tinydtls library.

This currently only implements the client side. To have a test server, run::

    $ git clone https://github.com/obgm/libcoap.git --recursive
    $ cd libcoap
    $ ./autogen.sh
    $ ./configure --with-tinydtls --disable-shared --disable-documentation
    $ make
    $ ./examples/coap-server -k secretPSK

(Using TinyDTLS in libcoap is important; with the default OpenSSL build, I've
seen DTLS1.0 responses to DTLS1.3 requests, which are hard to debug.)

The test server with its built-in credentials can then be accessed using::

    $ echo '{"coaps://localhost/*": {"dtls": {"psk": {"ascii": "secretPSK"}, "client-identity": {"ascii": "client_Identity"}}}}' > testserver.json
    $ ./aiocoap-client coaps://localhost --credentials testserver.json

While it is planned to allow more programmatical construction of the
credentials store, the currently recommended way of storing DTLS credentials is
to load a structured data object into the client_credentials store of the context:

>>> c = await aiocoap.Context.create_client_context()          # doctest: +SKIP
>>> c.client_credentials.load_from_dict(
...     {'coaps://localhost/*': {'dtls': {
...         'psk': b'secretPSK',
...         'client-identity': b'client_Identity',
...         }}})                                               # doctest: +SKIP

where, compared to the JSON example above, byte strings can be used directly
rather than expressing them as 'ascii'/'hex' (`{'hex': '30383135'}` style works
as well) to work around JSON's limitation of not having raw binary strings.

Bear in mind that the aiocoap CoAPS support is highly experimental; for
example, while requests to this server do complete, error messages are still
shown during client shutdown.
"""

import asyncio
import weakref
import functools
import time

from ..util.asyncio import PeekQueue
from ..util import hostportjoin, hostportsplit
from ..message import Message
from .. import interfaces, error
from ..numbers import COAPS_PORT
from ..credentials import CredentialsMissingError

# tinyDTLS passes address information around in its session data, but the way
# it's used here that will be ignored; this is the data that is sent to / read
# from the tinyDTLS functions
_SENTINEL_ADDRESS = "::1"
_SENTINEL_PORT = 1234

DTLS_EVENT_CONNECT = 0x01DC
DTLS_EVENT_CONNECTED = 0x01DE
DTLS_EVENT_RENEGOTIATE = 0x01DF

LEVEL_NOALERT = 0 # seems only to be issued by tinydtls-internal events

# from RFC 5246
LEVEL_WARNING = 1
LEVEL_FATAL = 2
CODE_CLOSE_NOTIFY = 0

# tinydtls can not be debugged in the Python way; if you need to get more
# information out of it, use the following line:
#dtls.setLogLevel(0xff)

# FIXME this should be exposed by the dtls wrapper
DTLS_TICKS_PER_SECOND = 1000
DTLS_CLOCK_OFFSET = time.time()

class DTLSClientConnection(interfaces.EndpointAddress):
    # for now i'd assyme the connection can double as an address. this means it
    # must be able to reconnect, and to manage itself as a member of a pool.

    # actually .remote probably needs to be split into different aspects, and
    # then this will fall apart; in particular:
    # * "Address where this must come from in order to match the request"
    # * "Address where to send a package that I want to send to where I
    #    previously sent something else" (and my own address might have changed)
    # * possibly something else too
    #
    # maybe this can become something like "connection identified by initial
    # parameters that will try to keep a persistent security context, but will
    # fail over to doing something else (eg. establishing a new security
    # context or using another source ip) based on the original parameters if
    # that's possible (a client connection will always be able to do that, with
    # a server's side that'll probably fail permanently), and anyway indicate
    # what happens"?
    #
    # for now i'm ignoring that (FIXME this means that some MUST of the spec
    # are not met!)

    # FIXME not only does this not do error handling, it seems not to even
    # survive its 2**16th message exchange.

    is_multicast = False
    is_multicast_locally = False
    hostinfo = None # stored at initualization time
    uri_base = property(lambda self: 'coaps://' + self.hostinfo)
    # Not necessarily very usable given we don't implement responding to server
    # connection, but valid anyway
    uri_base_local = property(lambda self: 'coaps://' + self.hostinfo_local)
    scheme = 'coaps'

    @property
    def hostinfo_local(self):
        # See TCP's.hostinfo_local
        host, port, *_ = self._transport.get_extra_info('socket').getsockname()
        if port == COAPS_PORT:
            port = None
        return hostportjoin(host, port)

    def __init__(self, host, port, pskId, psk, coaptransport):
        self._ready = False
        self._queue = PeekQueue() # stores sent packages while connection
            # is being built. for the above reasons of "this must be able to
            # reconnect", we must always be able to enqueue the package, even
            # though most times it will just be sent right away. the
            # transmission throttling of Protocol will make sure that this
            # doesn't really fill up.

        self._host = host
        self._port = port
        self._pskId = pskId
        self._psk = psk
        self.coaptransport = coaptransport
        self.hostinfo = hostportjoin(host, None if port == COAPS_PORT else port)

        self._task = asyncio.ensure_future(self._run(connect_immediately=True))

    def send(self, message):
        self._queue.put_nowait(message)

    log = property(lambda self: self.coaptransport.log)

    async def _run(self, connect_immediately):
        from DTLSSocket import dtls

        self._dtls_socket = None

        if not connect_immediately:
            await self._queue.peek()

        self._connection = None

        try:
            self._transport, singleconnection = await self.coaptransport.loop.create_datagram_endpoint(
                    self.SingleConnection.factory(self),
                    remote_addr=(self._host, self._port),
                    )

            self._dtls_socket = dtls.DTLS(
                    read=self._read,
                    write=self._write,
                    event=self._event,
                    pskId=self._pskId,
                    pskStore={self._pskId: self._psk},
                    )
            self._connection = self._dtls_socket.connect(_SENTINEL_ADDRESS, _SENTINEL_PORT)

            self._retransmission_task = asyncio.Task(self._run_retransmissions())

            self._connecting = asyncio.Future()

            await self._connecting

            while True:
                message = await self._queue.get()
                self._retransmission_task.cancel()
                self._dtls_socket.write(self._connection, message)
                self._retransmission_task = asyncio.Task(self._run_retransmissions())
        except OSError as e:
            self.log.debug("Expressing exception %r as errno %d.", e, e.errno)
            self.coaptransport.ctx.dispatch_error(e.errno, self)
        except Exception as e:
            self.log.error("Exception %r can not be represented as errno, setting -1.", e)
            self.coaptransport.ctx.dispatch_error(-1, self)
        finally:
            if self._connection is not None:
                try:
                    self._dtls_socket.close(self._connection)
                except:
                    pass # _dtls_socket actually does raise an empty Exception() here
                self._retransmission_task.cancel()
            # doing this here allows the dtls socket to send a final word, but
            # by closing this, we protect the nascent next connection from any
            # delayed ICMP errors that might still wind up in the old socket
            self._transport.close()

    async def _run_retransmissions(self):
        while True:
            when = self._dtls_socket.checkRetransmit() / DTLS_TICKS_PER_SECOND
            if when == 0:
                return
            now = time.time() - DTLS_CLOCK_OFFSET
            await asyncio.sleep(when - now)


    def shutdown(self):
        self._task.cancel()

    def _cancelled(self):
        self._task.cancel()
        self._task = asyncio.ensure_future(self._run(connect_immediately=False))

    # dtls callbacks

    def _read(self, sender, data):
        # ignoring sender: it's only _SENTINEL_*

        try:
            message = Message.decode(data, self)
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s", sender)
            return len(data)

        self.coaptransport.ctx.dispatch_message(message)

        return len(data)

    def _write(self, recipient, data):
        # ignoring recipient: it's only _SENTINEL_*
        try:
            t = self._transport
        except:
            # tinydtls sends callbacks very very late during shutdown (ie.
            # `hasattr` and `AttributeError` are all not available any more,
            # and even if the DTLSClientConnection class had a ._transport, it
            # would already be gone), and it seems even a __del__ doesn't help
            # break things up into the proper sequence.
            return 0
        t.sendto(data)
        return len(data)

    def _event(self, level, code):
        if (level, code) == (LEVEL_NOALERT, DTLS_EVENT_CONNECT):
            return
        elif (level, code) == (LEVEL_NOALERT, DTLS_EVENT_CONNECTED):
            self._connecting.set_result(True)
        elif (level, code) == (LEVEL_FATAL, CODE_CLOSE_NOTIFY):
            self._cancelled()
        elif level == LEVEL_FATAL:
            self.log.error("Fatal DTLS error: code %d", code)
            self._cancelled()
        else:
            self.log.warning("Unhandled alert level %d code %d", level, code)

    # transport protocol

    class SingleConnection:
        @classmethod
        def factory(cls, parent):
            return functools.partial(cls, parent)

        def __init__(self, parent):
            self.parent = parent #: DTLSClientConnection

        def connection_made(self, transport):
            pass # already handled in .start()

        def connection_lost(self, exc):
            pass

        def error_received(self, exc):
            self.parent.log.warning("Error received in UDP connection under DTLS: %s", exc)
            self.parent._task.cancel()

        def datagram_received(self, data, addr):
            self.parent._dtls_socket.handleMessage(self.parent._connection, data)

class MessageInterfaceTinyDTLS(interfaces.MessageInterface):
    def __init__(self, ctx: interfaces.MessageManager, log, loop):
        self._pool = weakref.WeakValueDictionary({}) # see _connection_for_address

        self.ctx = ctx

        self.log = log
        self.loop = loop

    async def _connection_for_address(self, host, port, pskId, psk):
        """Return a DTLSConnection to a given address. This will always give
        the same result for the same host/port combination, at least for as
        long as that result is kept alive (eg. by messages referring to it in
        their .remote)."""

        try:
            return self._pool[(host, port, pskId)]
        except KeyError:
            connection = DTLSClientConnection(host, port, pskId, psk, self)
            self._pool[(host, port, pskId)] = connection
            return connection

    @classmethod
    async def create_client_transport_endpoint(cls, ctx: interfaces.MessageManager, log, loop):
        return cls(ctx, log, loop)

    async def recognize_remote(self, remote):
        return isinstance(remote, DTLSClientConnection) and remote in self._pool.values()

    async def determine_remote(self, request):
        if request.requested_scheme != 'coaps':
            return None

        if request.unresolved_remote:
            host, port = hostportsplit(request.unresolved_remote)
            port = port or COAPS_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAPS_PORT
        else:
            raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

        dtlsparams = self.ctx.client_credentials.credentials_from_request(request)
        try:
            pskId, psk = dtlsparams.as_dtls_psk()
        except AttributeError:
            raise CredentialsMissingError("Credentials for requested URI are not compatible with DTLS-PSK")
        result = await self._connection_for_address(host, port, pskId, psk)
        return result

    def send(self, message):
        message.remote.send(message.encode())

    async def shutdown(self):
        remaining_connections = list(self._pool.values())
        for c in remaining_connections:
            c.shutdown()
