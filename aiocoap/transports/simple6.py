# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a TransportEndpoint for UDP based on the asyncio
DatagramProtocol.

This is a simple version that works only for clients (by creating a dedicated
unbound but connected socket for each communication partner) and probably not
with multicast (it is assumed to be unsafe for multicast), which can be
expected to work even on platforms where the :mod:`.udp6` module can not be
made to work (Android, OSX, Windows for missing ``recvmsg`` and socket options,
uvloop because :class:`.util.asyncio.RecvmsgSelectorDatagramTransport` is not
implemented there).

This transport is experimental, likely to change, and not fully tested yet
(because the test suite is not yet ready to matrix-test the same tests with
different transport implementations, and because it still fails in proxy
blockwise tests).
"""

import urllib
import asyncio
import socket

from aiocoap import interfaces, error
from aiocoap import Message, COAP_PORT
from ..util import hostportjoin
from .generic_udp import GenericTransportEndpoint

class _Connection(asyncio.DatagramProtocol, interfaces.EndpointAddress):
    def __init__(self, ready_callback, new_message_callback, new_error_callback, stored_sockaddr):
        self._ready_callback = ready_callback
        self._new_message_callback = new_message_callback
        self._new_error_callback = new_error_callback

        # This gets stored in the _Connection because not all implementations
        # of datagram transports will expose the get_extra_info('socket')
        # (right now, all I knew do), or their backend might not be a connected
        # socket (like in uvloop), so the information can't be just obtained
        # from the transport, but is needed to implement .hostinfo
        #
        # If _Connections become used in other contexts (eg. tinydtls starts
        # using them), it might be a good idea to move all this into a subclass
        # and split it from the pure networking stuff.
        self.hostinfo = hostportjoin(stored_sockaddr[0], None if stored_sockaddr[1] == COAP_PORT else stored_sockaddr[1])
        self.uri = 'coap://' + self.hostinfo

        self._stage = "initializing" #: Status property purely for debugging

    def __repr__(self):
        return "<%s at %#x on transport %s, %s>" % (
                type(self).__name__,
                id(self),
                getattr(self, "_transport", "(none)"),
                self._stage)

    # address interface

    is_multicast = False

    is_multicast_locally = False

    # statically initialized in init
    hostinfo = None
    uri = None

# fully disabled because some implementations of asyncio don't make the
# information available; going the easy route and storing it for all (see
# attribute population in __init__)

#     # FIXME continued: probably this is, and the above is not (or should not be)
#     @property
#     def hostinfo(self):
#         print("ACCESSING HOSTINFO")
#         host, port = self._transport.get_extra_info('socket').getpeername()[:2]
#         if port == COAP_PORT:
#             port = None
#         # FIXME this should use some of the _plainaddress mechanisms of the udp6 addresses
#         return hostportjoin(host, port)

    # datagram protocol interface

    def connection_made(self, transport):
        self._transport = transport
        self._ready_callback()
        self._stage = "active"
        del self._ready_callback

    def datagram_received(self, data, address):
        self._new_message_callback(self, data)

    def error_received(self, exception):
        self._new_error_callback(self, exception)

    def connection_lost(self, exception):
        if exception is None:
            pass
        else:
            self._new_error_callback(self, exception)

    # whatever it is _DatagramClientSocketpoolSimple6 expects

    def send(self, data):
        self._transport.sendto(data, None)

    @asyncio.coroutine
    def shutdown(self):
        self._stage = "shutting down"
        self._transport.abort()
        del self._new_message_callback
        del self._new_error_callback
        self._stage = "destroyed"

class _DatagramClientSocketpoolSimple6:
    """This class is used to explore what an Python/asyncio abstraction around
    a hypothetical "UDP connections" mechanism could look like.

    Assume there were a socket variety that had UDP messages (ie. unreliable,
    unordered, boundary-preserving) but that can do an accept() like a TCP
    listening socket can, and can create outgoing connection-ish sockets from
    the listeing port.

    That interface would be usable for all UDP-based CoAP transport
    implementations; this particular implementation, due to limitations of
    POSIX sockets (and the additional limitations imposed on it like not using
    PKTINFO) provides the interface, but only implements the outgoing part, and
    will not allow setting the outgoing port or interface."""

    # FIXME (new_message_callback, new_error_callback) should probably rather
    # be one object with a defined interface; either that's the
    # TransportEndpointSimple6 and stored accessibly (so the Protocol can know
    # which TransportEndpoint to talk to for sending), or we move the
    # TransportEndpoint out completely and have that object be the Protocol,
    # and the Protocol can even send new packages via the address
    def __init__(self, loop, new_message_callback, new_error_callback):
        # currently tracked only for shutdown
        self._sockets = []

        self._loop = loop
        self._new_message_callback = new_message_callback
        self._new_error_callback = new_error_callback

    @asyncio.coroutine
    def connect(self, sockaddr):
        """Create a new socket with a given remote socket address

        Note that the sockaddr does not need to be fully resolved or complete,
        as it is not used for matching incoming packages; ('host.example.com',
        5683) is perfectly OK (and will create a different outgoing socket that
        ('hostalias.example.com', 5683) even if that has the same address, for
        better or for worse).

        For where the general underlying interface is concerned, it is not yet
        fixed at all when this must return identical objects."""

        ready = asyncio.Future()
        transport, protocol = yield from self._loop.create_datagram_endpoint(
                lambda: _Connection(lambda: ready.set_result(None), self._new_message_callback, self._new_error_callback, sockaddr),
                family=socket.AF_INET6,
                flags=socket.AI_V4MAPPED,
                remote_addr=sockaddr)
        yield from ready

        # FIXME twice: 1., those never get removed yet (should timeout or
        # remove themselves on error), and 2., this is racy against a shutdown right after a connect
        self._sockets.append(protocol)

        return protocol

    @asyncio.coroutine
    def shutdown(self):
        if self._sockets:
            yield from asyncio.wait([s.shutdown() for s in self._sockets])
        del self._sockets

class TransportEndpointSimple6(GenericTransportEndpoint):
    @classmethod
    @asyncio.coroutine
    def create_client_transport_endpoint(cls, new_message_callback, new_error_callback, log, loop):
        self = cls(new_message_callback, new_error_callback, log, loop)

        self._pool = _DatagramClientSocketpoolSimple6(self._loop, self._received_datagram, self._received_exception)
        return self
