# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a TransportEndpoint for UDP based on the asyncio
DatagramProtocol.

As this makes use of RFC 3542 options (IPV6_PKTINFO), this is likely to only
work with IPv6 interfaces. Hybrid stacks are supported, though, so V4MAPPED
addresses (a la `::ffff:127.0.0.1`) will be used when name resolution shows
that a name is only available on V4."""

import asyncio

from ..message import Message
from .. import error
from .. import interfaces

class TransportEndpointUDP6(asyncio.DatagramProtocol, interfaces.TransportEndpoint):
    def __init__(self, context, log, loop):
        self.context = context
        self.log = log
        self.loop = loop

        self._shutting_down = None #: Future created and used in the .shutdown() method.

        self.ready = asyncio.Future() #: Future that gets fullfilled by connection_made (ie. don't send before this is done; handled by ``create_..._context``

    @asyncio.coroutine
    def shutdown(self):
        self._shutting_down = asyncio.Future()

        self.transport.close()

        yield from self._shutting_down

        del self.context

    def send(self, message, remote):
        self.transport.sendto(message.encode(), remote)

    # where should that go?
    #transport._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, 1)

    #
    # implementing the typical DatagramProtocol interfaces.
    #
    # note from the documentation: we may rely on connection_made to be called
    # before datagram_received -- but sending immediately after context
    # creation will still fail

    def connection_made(self, transport):
        """Implementation of the DatagramProtocol interface, called by the transport."""
        self.ready.set_result(True)
        self.transport = transport

    def datagram_received(self, data, address):
        """Implementation of the DatagramProtocol interface, called by the transport."""
        try:
            message = Message.decode(data, address)
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s"%(address,))
            return

        self.context._dispatch_message(message)

    def error_received(self, exc):
        """Implementation of the DatagramProtocol interface, called by the transport."""
        # TODO: set IP_RECVERR to receive icmp "destination unreachable (port
        # unreachable)" & co to stop retransmitting and err back quickly
        self.log.error("Error received: %s"%exc)

    def connection_lost(self, exc):
        # TODO better error handling -- find out what can cause this at all
        # except for a shutdown
        if exc is not None:
            self.log.error("Connection lost: %s"%exc)

        if self._shutting_down is None:
            self.log.error("Connection loss was not expected.")
        else:
            self._shutting_down.set_result(None)
