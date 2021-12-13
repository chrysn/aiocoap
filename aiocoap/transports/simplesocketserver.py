# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a MessageInterface for UDP based on the asyncio
DatagramProtocol.

This is a simple version that works only for servers bound to a single unicast
address. It provides a server backend in situations when :mod:`.udp6` is
unavailable and :mod:`.simple6` needs to be used for clients.

While it is in theory capable of sending requests too, it should not be used
like that, because it won't receive ICMP errors (see below).

Shortcomings
------------

* This implementation does not receive ICMP errors. This violates the CoAP
  standard and can lead to unnecessary network traffic, bad user experience
  (when used for client requests) or even network attack amplification.

* The server can not be used with the "any-address" (``::``, ``0.0.0.0``).
  If it were allowed to bind there, it would not receive any indication from the operating system
  as to which of its own addresses a request was sent,
  and could not send the response with the appropriate sender address.

  (The :mod:`udp6<aiocoap.transports.udp6>` transport does not suffer that shortcoming,
  simplesocketserver is typically only used when that is unavailable).

  With simplesocketserver, you need to explicitly give the IP address of your server
  in the ``bind`` argument of :meth:`aiocoap.protocol.Context.create_server_context`.

* This transport is experimental and likely to change.
"""

import asyncio
from collections import namedtuple

from .. import error
from ..numbers import COAP_PORT
from .. import interfaces
from .generic_udp import GenericMessageInterface
from ..util import hostportjoin
from .. import defaults

class _Address(namedtuple('_Address', ['serversocket', 'address']), interfaces.EndpointAddress):
    # hashability and equality follow from being a namedtuple
    def __repr__(self):
        return '<%s.%s via %s to %s>'%(__name__, type(self).__name__, self.serversocket, self.address)

    def send(self, data):
        self.serversocket._transport.sendto(data, self.address)

    # EnpointAddress interface

    is_multicast = False
    is_multicast_locally = False

    @property
    def hostinfo(self):
        # `host` already contains the interface identifier, so throwing away
        # scope and interface identifier
        host, port, *_ = self.address
        if port == COAP_PORT:
            port = None
        return hostportjoin(host, port)

    @property
    def uri_base(self):
        return self.scheme + '://' + self.hostinfo

    @property
    def hostinfo_local(self):
        return self.serversocket.hostinfo_local

    @property
    def uri_base_local(self):
        return self.scheme + '://' + self.hostinfo_local

    scheme = 'coap'

    @property
    def blockwise_key(self):
        return self.address

class _DatagramServerSocketSimple(asyncio.DatagramProtocol):
    # To be overridden by tinydtls_server
    _Address = _Address

    @classmethod
    async def create(cls, bind, log, loop, message_interface: "GenericMessageInterface"):
        if bind is None or bind[0] in ('::', '0.0.0.0', '', None):
            # If you feel tempted to remove this check, think about what
            # happens if two configured addresses can both route to a
            # requesting endpoint, how that endpoint is supposed to react to a
            # response from the other address, and if that case is not likely
            # to ever happen in your field of application, think about what you
            # tell the first user where it does happen anyway.
            raise ValueError("The transport can not be bound to any-address.")

        ready = asyncio.get_running_loop().create_future()

        transport, protocol = await loop.create_datagram_endpoint(
                lambda: cls(ready.set_result, message_interface, log),
                local_addr=bind,
                reuse_port=defaults.has_reuse_port(),
                )

        # Conveniently, we only bind to a single port (because we need to know
        # the return address, not because we insist we know the local
        # hostinfo), and can thus store the local hostinfo without distinction
        protocol.hostinfo_local = hostportjoin(bind[0], bind[1] if bind[1] != COAP_PORT else None)

        self = await ready
        self._loop = loop
        return self

    def __init__(self, ready_callback, message_interface: "GenericMessageInterface", log):
        self._ready_callback = ready_callback
        self._message_interface = message_interface
        self.log = log

    async def shutdown(self):
        self._transport.abort()

    # interface like _DatagramClientSocketpoolSimple6

    async def connect(self, sockaddr):
        # FIXME this is not regularly tested either

        self.log.warning("Sending initial messages via a server socket is not recommended")
        # A legitimate case is when something stores return addresses as
        # URI(part)s and not as remotes. (In similar transports this'd also be
        # the case if the address's connection is dropped from the pool, but
        # that doesn't happen here since there is no pooling as there is no
        # per-connection state).

        # getaddrinfo is not only to needed to resolve any host names (which
        # would not be recognized otherwise), but also to get a complete (host,
        # port, zoneinfo, whatwasthefourth) tuple from what is passed in as a
        # (host, port) tuple.
        addresses = await self._loop.getaddrinfo(*sockaddr, family=self._transport.get_extra_info('socket').family)
        if not addresses:
            raise error.NetworkError("No addresses found for %s" % sockaddr[0])
        # FIXME could do happy eyebals
        address = addresses[0][4]
        address = self._Address(self, address)
        return address

    # datagram protocol interface

    def connection_made(self, transport):
        self._transport = transport
        self._ready_callback(self)
        del self._ready_callback

    def datagram_received(self, data, sockaddr):
        self._message_interface._received_datagram(self._Address(self, sockaddr), data)

    def error_received(self, exception):
        # This is why this whole implementation is a bad idea (but still the best we got on some platforms)
        self.log.warning("Ignoring error because it can not be mapped to any connection: %s", exception)

    def connection_lost(self, exception):
        if exception is None:
            pass # regular shutdown
        else:
            self.log.error("Received unexpected connection loss: %s", exception)

class MessageInterfaceSimpleServer(GenericMessageInterface):
    # for alteration by tinydtls_server
    _default_port = COAP_PORT
    _serversocket = _DatagramServerSocketSimple

    @classmethod
    async def create_server(cls, bind, ctx: interfaces.MessageManager, log, loop):
        self = cls(ctx, log, loop)
        bind = bind or ('::', None)
        # Interpret None as 'default port', but still allow to bind to 0 for
        # servers that want a random port (eg. when the service URLs are
        # advertised out-of-band anyway). LwM2M clients should use simple6
        # instead as outlined there.
        bind = (bind[0], self._default_port if bind[1] is None else bind[1] + (self._default_port - COAP_PORT))

        # Cyclic reference broken during shutdown
        self._pool = await self._serversocket.create(bind, log, self._loop, self)

        return self

    async def recognize_remote(self, remote):
        # FIXME: This is never tested (as is the connect method) because all
        # tests create client contexts client-side (which don't build a
        # simplesocketserver), and because even when a server context is
        # created, there's a simple6 that grabs such addresses before a request
        # is sent out
        return isinstance(remote, _Address) and remote.serversocket is self._pool
