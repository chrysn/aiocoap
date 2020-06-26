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

from ..numbers import COAP_PORT
from .. import interfaces
from .generic_udp import GenericMessageInterface
from ..util import hostportjoin
from .. import defaults

class _Address(namedtuple('_Address', ['serversocket', 'address']), interfaces.EndpointAddress):
    # hashability and equality follow from being a namedtuple
    def __repr__(self):
        return '<%s via %s to %s>'%(type(self).__name__, self.serversocket, self.address)

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

class _DatagramServerSocketSimple(asyncio.DatagramProtocol):
    @classmethod
    async def create(cls, bind, log, loop, new_message_callback, new_error_callback):
        if bind is None or bind[0] in ('::', '0.0.0.0', '', None):
            # If you feel tempted to remove this check, think about what
            # happens if two configured addresses can both route to a
            # requesting endpoint, how that endpoint is supposed to react to a
            # response from the other address, and if that case is not likely
            # to ever happen in your field of application, think about what you
            # tell the first user where it does happen anyway.
            raise ValueError("The transport can not be bound to any-address.")

        ready = asyncio.Future()

        transport, protocol = await loop.create_datagram_endpoint(
                lambda: cls(ready.set_result, new_message_callback, new_error_callback, log),
                local_addr=bind,
                reuse_port=defaults.has_reuse_port(),
                )

        # Conveniently, we only bind to a single port (because we need to know
        # the return address, not because we insist we know the local
        # hostinfo), and can thus store the local hostinfo without distinction
        protocol.hostinfo_local = hostportjoin(bind[0], bind[1] if bind[1] != COAP_PORT else None)

        return await ready

    def __init__(self, ready_callback, new_message_callback, new_error_callback, log):
        self._ready_callback = ready_callback
        self._new_message_callback = new_message_callback
        self._new_error_callback = new_error_callback
        self.log = log

    async def shutdown(self):
        self._transport.abort()

    # interface like _DatagramClientSocketpoolSimple6

    async def connect(self, sockaddr):
        # FIXME it might be necessary to resolve the address now to get a
        # canonical form that can be recognized later when a package comes back
        self.log.warning("Sending initial messages via a server socket is not recommended")
        return _Address(self, sockaddr)

    # datagram protocol interface

    def connection_made(self, transport):
        self._transport = transport
        self._ready_callback(self)
        del self._ready_callback

    def datagram_received(self, data, address):
        self._new_message_callback(_Address(self, address), data)

    def error_received(self, exception):
        # This is why this whole implementation is a bad idea (but still the best we got on some platforms)
        self.log.warning("Ignoring error because it can not be mapped to any connection: %s", exception)

    def connection_lost(self, exception):
        if exception is None:
            pass
        else:
            self.log.error("Received unexpected connection loss: %s", exception)

class MessageInterfaceSimpleServer(GenericMessageInterface):
    @classmethod
    async def create_server(cls, bind, ctx: interfaces.MessageManager, log, loop):
        self = cls(ctx, log, loop)
        bind = bind or ('::', None)
        # Interpret None as 'default port', but still allow to bind to 0 for
        # servers that want a random port (eg. when the service URLs are
        # advertised out-of-band anyway). LwM2M clients should use simple6
        # instead as outlined there.
        bind = (bind[0], COAP_PORT if bind[1] is None else bind[1])

        self._pool = await _DatagramServerSocketSimple.create(bind, log, self._loop, self._received_datagram, self._received_exception)

        return self

    async def recognize_remote(self, remote):
        return isinstance(remote, _Address) and remote in remote.serversocket is self._pool
