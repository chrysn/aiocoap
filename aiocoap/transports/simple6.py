# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a MessageInterface for UDP based on the asyncio
DatagramProtocol.

This is a simple version that works only for clients (by creating a dedicated
unbound but connected socket for each communication partner) and probably not
with multicast (it is assumed to be unsafe for multicast), which can be
expected to work even on platforms where the :mod:`.udp6` module can not be
made to work (Android, OSX, Windows for missing ``recvmsg`` and socket options,
or any event loops that don't have an add_reader method).

Note that the name of the module is a misnomer (and the module is likely to be
renamed): Nothing in it is IPv6 specific; the socket is created using whichever
address family the OS chooses based on the given host name.

One small but noteworthy detail about this transport is that it does not
distinguish between IP literals and host names. As a result, requests and
responses from remotes will appear to arrive from a remote whose netloc is the
requested name, not an IP literal.

This transport is experimental, likely to change, and not fully tested yet
(because the test suite is not yet ready to matrix-test the same tests with
different transport implementations, and because it still fails in proxy
blockwise tests).

For one particular use case, this may be usable for servers in a sense: If (and
only if) all incoming requests are only ever sent from clients that were
previously addressed as servers by the running instance. (This is generally
undesirable as it greatly limits the usefulness of the server, but is used in
LwM2M setups). As such a setup makes demands on the peer that are not justified
by the CoAP specification (in particular, that it send requests from a
particular port), this should still only be used for cases where the udp6
transport is unavailable due to platform limitations.
"""

import asyncio
import socket
from collections import OrderedDict

from aiocoap import interfaces
from aiocoap import COAP_PORT
from ..util import hostportjoin
from .generic_udp import GenericMessageInterface

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

    scheme = 'coap'

    # statically initialized in init
    hostinfo = None
    uri_base = None
    uri_base = property(lambda self: 'coap://' + self.hostinfo)

    @property
    def hostinfo_local(self):
        # This can only be done on a best-effort base here. Unlike the below
        # hostinfo (see comments there), there is no easy way around this, so
        # if there are still implementations out that don't do the extras,
        # that's it and the calling site should reconsider whether they need
        # something that can not be determined. (Some more effort could go into
        # falling back to get_extra_info('socket').getsockname(), but that
        # should really be fixed in the transport provider).
        if not hasattr(self, '_transport'):
            raise RuntimeError("Simple6 does not have defined local host info in current stage %s" % self._stage)
        sockname = self._transport.get_extra_info('sockname')
        if sockname is None:
            raise RuntimeError("Simple6 can not determine local address from the underlying UDP implementation")
        return hostportjoin(*sockname[:2])
    uri_base_local = property(lambda self: 'coap://' + self.hostinfo_local)

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

    async def shutdown(self):
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

    max_sockets = 64

    # FIXME (new_message_callback, new_error_callback) should probably rather
    # be one object with a defined interface; either that's the
    # MessageInterfaceSimple6 and stored accessibly (so the Protocol can know
    # which MessageInterface to talk to for sending), or we move the
    # MessageInterface out completely and have that object be the Protocol,
    # and the Protocol can even send new packages via the address
    def __init__(self, loop, new_message_callback, new_error_callback):
        # using an OrderedDict to implement an LRU cache as it's suitable for that purpose according to its documentation
        self._sockets = OrderedDict()

        self._loop = loop
        self._new_message_callback = new_message_callback
        self._new_error_callback = new_error_callback

    async def _maybe_purge_sockets(self):
        while len(self._sockets) >= self.max_sockets: # more of an if
            oldaddr, oldest = next(iter(self._sockets.items()))
            await oldest.shutdown()
            del self._sockets[oldaddr]

    async def connect(self, sockaddr):
        """Create a new socket with a given remote socket address

        Note that the sockaddr does not need to be fully resolved or complete,
        as it is not used for matching incoming packages; ('host.example.com',
        5683) is perfectly OK (and will create a different outgoing socket that
        ('hostalias.example.com', 5683) even if that has the same address, for
        better or for worse).

        For where the general underlying interface is concerned, it is not yet
        fixed at all when this must return identical objects."""

        protocol = self._sockets.get(sockaddr)
        if protocol is not None:
            self._sockets.move_to_end(sockaddr)
            return protocol

        await self._maybe_purge_sockets()

        ready = asyncio.Future()
        transport, protocol = await self._loop.create_datagram_endpoint(
                lambda: _Connection(lambda: ready.set_result(None), self._new_message_callback, self._new_error_callback, sockaddr),
                remote_addr=sockaddr)
        await ready

#         # Enable this to easily make every connection to localhost a new one
#         # during testing
#         import random
#         sockaddr = sockaddr + (random.random(),)

        # FIXME twice: 1., those never get removed yet (should timeout or
        # remove themselves on error), and 2., this is racy against a shutdown right after a connect
        self._sockets[sockaddr] = protocol

        return protocol

    async def shutdown(self):
        if self._sockets:
            done, pending = await asyncio.wait([s.shutdown() for s in self._sockets.values()])
            for item in done:
                await item
        del self._sockets

class MessageInterfaceSimple6(GenericMessageInterface):
    @classmethod
    async def create_client_transport_endpoint(cls, ctx, log, loop):
        self = cls(ctx, log, loop)

        self._pool = _DatagramClientSocketpoolSimple6(self._loop, self._received_datagram, self._received_exception)
        return self

    async def recognize_remote(self, remote):
        return isinstance(remote, _Connection) and remote in self._pool._sockets
