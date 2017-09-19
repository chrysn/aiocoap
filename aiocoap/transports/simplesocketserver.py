# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a TransportEndpoint for UDP based on the asyncio
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

* This transport is experimental and likely to change.
"""

import asyncio
from collections import namedtuple

from .simple6 import TransportEndpointSimple6 as _TransportEndpointSimple6
from .. import interfaces
from .generic_udp import GenericTransportEndpoint

class _Address(namedtuple('_Address', ['serversocket', 'address']), interfaces.EndpointAddress):
    # hashability and equality follow from being a namedtuple
    def __repr__(self):
        return '<%s via %s to %s>'%(type(self).__name__, self.serversocket, self.address)

    def send(self, data):
        self.serversocket._transport.sendto(data, self.address)

    # EnpointAddress interface

    is_multicast = False
    is_multicast_locally = False

class _DatagramServerSocketSimple(asyncio.DatagramProtocol):
    @classmethod
    @asyncio.coroutine
    def create(cls, server_address, log, loop, new_message_callback, new_error_callback):
        if server_address[0] in ('::', '0.0.0.0', ''):
            # If you feel tempted to remove this check, think about what
            # happens if two configured addresses can both route to a
            # requesting endpoint, how that endpoint is supposed to react to a
            # response from the other address, and if that case is not likely
            # to ever happen in your field of application, think about what you
            # tell the first user where it does happen anyway.
            raise ValueError("The transport can not be bound to any-address.")

        ready = asyncio.Future()

        transport, protocol = yield from loop.create_datagram_endpoint(
                lambda: cls(ready.set_result, new_message_callback, new_error_callback, log),
                local_addr=server_address,
                reuse_address=True,
                )

        return (yield from ready)

    def __init__(self, ready_callback, new_message_callback, new_error_callback, log):
        self._ready_callback = ready_callback
        self._new_message_callback = new_message_callback
        self._new_error_callback = new_error_callback
        self.log = log

    @asyncio.coroutine
    def shutdown(self):
        self._transport.abort()

    # interface like _DatagramClientSocketpoolSimple6

    @asyncio.coroutine
    def connect(self, sockaddr):
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

class TransportEndpointSimpleServer(GenericTransportEndpoint):
    @classmethod
    @asyncio.coroutine
    def create_server(cls, server_address, new_message_callback, new_error_callback, log, loop):
        self = cls(new_message_callback, new_error_callback, log, loop)

        self._pool = yield from _DatagramServerSocketSimple.create(server_address, log, self._loop, self._received_datagram, self._received_exception)

        return self
