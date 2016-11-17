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
import urllib.parse
import socket
import ipaddress
import struct
from collections import namedtuple

from ..message import Message
from .. import error
from .. import interfaces
from ..numbers import COAP_PORT
from ..dump import TextDumper
from ..util.asyncio import RecvmsgDatagramProtocol
from ..util import hostportjoin
from ..util import socknumbers

class UDP6EndpointAddress:
    # interface work in progress. chances are those should be immutable or at
    # least hashable, as they'll be frequently used as dict keys.
    def __init__(self, sockaddr, *, pktinfo=None):
        self.sockaddr = sockaddr
        self.pktinfo = pktinfo

    def __hash__(self):
        return hash(self.sockaddr)

    def __eq__(self, other):
        return self.sockaddr == other.sockaddr

    def __repr__(self):
        return "<%s [%s]:%d%s>"%(type(self).__name__, self.sockaddr[0], self.sockaddr[1], " with local address" if self.pktinfo is not None else "")

    @property
    def hostinfo(self):
        return hostportjoin(self.sockaddr[0], self.sockaddr[1] if self.sockaddr[1] != COAP_PORT else None)

    # those are currently the inofficial metadata interface
    port = property(lambda self: self.sockaddr[1])
    is_multicast = property(lambda self: ipaddress.ip_address(self.sockaddr[0].split('%', 1)[0]).is_multicast)

class SockExtendedErr(namedtuple("_SockExtendedErr", "ee_errno ee_origin ee_type ee_code ee_pad ee_info ee_data")):
    _struct = struct.Struct("IbbbbII")
    @classmethod
    def load(cls, data):
        # unpack_from: recvmsg(2) says that more data may follow
        return cls(*cls._struct.unpack_from(data))

class TransportEndpointUDP6(RecvmsgDatagramProtocol, interfaces.TransportEndpoint):
    def __init__(self, new_message_callback, new_error_callback, log, loop):
        self.new_message_callback = new_message_callback
        self.new_error_callback = new_error_callback
        self.log = log
        self.loop = loop

        self._shutting_down = None #: Future created and used in the .shutdown() method.

        self.ready = asyncio.Future() #: Future that gets fullfilled by connection_made (ie. don't send before this is done; handled by ``create_..._context``

    @classmethod
    @asyncio.coroutine
    def _create_transport_endpoint(cls, new_message_callback, new_error_callback, log, loop, dump_to, bind):
        protofact = lambda: cls(new_message_callback=new_message_callback, new_error_callback=new_error_callback, log=log, loop=loop)
        if dump_to is not None:
            protofact = TextDumper.endpointfactory(open(dump_to, 'w'), protofact)

        transport, protocol = yield from loop.create_datagram_endpoint(protofact, family=socket.AF_INET6)

        sock = transport._sock

        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socknumbers.IPV6_RECVERR, 1)
        # i'm curious why this is required; didn't IPV6_V6ONLY=0 already make
        # it clear that i don't care about the ip version as long as everything looks the same?
        sock.setsockopt(socket.IPPROTO_IP, socknumbers.IP_RECVERR, 1)

        if bind is not None:
            # FIXME: SO_REUSEPORT should be safer when available (no port hijacking), and the test suite should work with it just as well (even without). why doesn't it?
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(bind)

        if dump_to is not None:
            protocol = protocol.protocol

        yield from protocol.ready

        return protocol

    @classmethod
    @asyncio.coroutine
    def create_client_transport_endpoint(cls, new_message_callback, new_error_callback, log, loop, dump_to):
        return (yield from cls._create_transport_endpoint(new_message_callback, new_error_callback, log, loop, dump_to, None))

    @classmethod
    @asyncio.coroutine
    def create_server_transport_endpoint(cls, new_message_callback, new_error_callback, log, loop, dump_to, bind):
        return (yield from cls._create_transport_endpoint(new_message_callback, new_error_callback, log, loop, dump_to, bind))

    @asyncio.coroutine
    def shutdown(self):
        self._shutting_down = asyncio.Future()

        self.transport.close()

        yield from self._shutting_down

        del self.new_message_callback
        del self.new_error_callback

    def send(self, message):
        ancdata = []
        if message.remote.pktinfo is not None:
            ancdata.append((socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, message.remote.pktinfo))
        self.transport.sendmsg(message.encode(), ancdata, 0, message.remote.sockaddr)

    @asyncio.coroutine
    def fill_remote(self, request):
        if request.remote is None:
            if request.unresolved_remote is not None or request.opt.uri_host:
                ## @TODO this is very rudimentary; happy-eyeballs or
                # similar could be employed.

                if request.unresolved_remote is not None:
                    pseudoparsed = urllib.parse.SplitResult(None, request.unresolved_remote, None, None, None)
                    host = pseudoparsed.hostname
                    port = pseudoparsed.port or COAP_PORT
                else:
                    host = request.opt.uri_host
                    port = request.opt.uri_port or COAP_PORT

                addrinfo = yield from self.loop.getaddrinfo(
                    host,
                    port,
                    family=self.transport._sock.family,
                    type=0,
                    proto=self.transport._sock.proto,
                    flags=socket.AI_V4MAPPED,
                    )
                request.remote = UDP6EndpointAddress(addrinfo[0][-1])
            else:
                raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

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

    def datagram_msg_received(self, data, ancdata, flags, address):
        """Implementation of the RecvmsgDatagramProtocol interface, called by the transport."""
        pktinfo = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socket.IPV6_PKTINFO:
                pktinfo = cmsg_data
            else:
                self.log.info("Received unexpected ancillary data to recvmsg: level %d, type %d, data %r", cmsg_level, cmsg_type, cmsg_data)
        try:
            message = Message.decode(data, UDP6EndpointAddress(address, pktinfo=pktinfo))
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s"%(address,))
            return

        self.new_message_callback(message)

    def datagram_errqueue_received(self, data, ancdata, flags, address):
        assert flags == socket.MSG_ERRQUEUE
        pktinfo = None
        errno = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            assert cmsg_level == socket.IPPROTO_IPV6
            if cmsg_type == socknumbers.IPV6_RECVERR:
                errno = SockExtendedErr.load(cmsg_data).ee_errno
            elif cmsg_level == socket.IPPROTO_IPV6 and cmsg_type == socknumbers.IPV6_PKTINFO:
                pktinfo = cmsg_data
            else:
                self.log.info("Received unexpected ancillary data to recvmsg errqueue: level %d, type %d, data %r", cmsg_level, cmsg_type, cmsg_data)
        remote = UDP6EndpointAddress(address, pktinfo=pktinfo)

        # not trying to decode a message from data -- that works for
        # "connection refused", doesn't work for "no route to host", and
        # anyway, when an icmp error comes back, everything pending from that
        # port should err out.

        self.new_error_callback(errno, remote)

    def error_received(self, exc):
        """Implementation of the DatagramProtocol interface, called by the transport."""
        # TODO: what can we do about errors we *only* receive here? (eg. sending to 127.0.0.0)
        self.log.error("Error received and ignored in this codepath: %s"%exc)

    def connection_lost(self, exc):
        # TODO better error handling -- find out what can cause this at all
        # except for a shutdown
        if exc is not None:
            self.log.error("Connection lost: %s"%exc)

        if self._shutting_down is None:
            self.log.error("Connection loss was not expected.")
        else:
            self._shutting_down.set_result(None)
