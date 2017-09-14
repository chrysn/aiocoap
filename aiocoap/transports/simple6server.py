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
like that, because it won't receive ICMP errors. (That's bad for the server as
well because it creates amplification surface, but in a client it creates bad
user experience because requests to unavailable servers wait for timeout).

This transport is experimental and likely to change.
"""

import asyncio
from collections import namedtuple

from .simple6 import TransportEndpointSimple6 as _TransportEndpointSimple6

class _Address(namedtuple('_Address', ['serversocket', 'address'])):
    # hashability and equality follow from being a namedtuple
    def __repr__(self):
        return '<%s via %s to %s>'%(type(self).__name__, self.serversocket, self.address)

    def send(self, data):
        self.serversocket._transport.sendto(data, self.address)

    # .remote interface

    @property
    def is_multicast(self):
        return False

class _DatagramServerSocketSimple6(asyncio.DatagramProtocol):
    @classmethod
    @asyncio.coroutine
    def create(cls, server_address, log, loop, new_message_callback, new_error_callback):
        ready = asyncio.Future()

        transport, protocol = yield from loop.create_datagram_endpoint(
                lambda: cls(ready.set_result, new_message_callback, new_error_callback, log),
                local_addr=server_address)

        return (yield from ready)

    def __init__(self, ready_callback, new_message_callback, new_error_callback, log):
        self._ready_callback = ready_callback
        self._new_message_callback = new_message_callback
        self._new_error_callback = new_error_callback
        self.log = log

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

class TransportEndpointSimple6Server(_TransportEndpointSimple6):
    # FIXME the creation interface towards Context is horrible ("await
    # create_server(address) and don't call __init__ yourself like in
    # simple6"), but the gist of the simple6 and this version will need to be
    # factored out anyway.

    @classmethod
    @asyncio.coroutine
    def create_server(cls, server_address, new_message_callback, new_error_callback, log, loop):
        self = cls(new_message_callback, new_error_callback, log, loop)

        self._pool = yield from _DatagramServerSocketSimple6.create(server_address, log, self._loop, self._received_datagram, self._received_exception)

        return self

