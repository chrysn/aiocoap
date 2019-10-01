# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a MessageInterface for UDP based on a variation of
the asyncio DatagramProtocol.

This implementation strives to be correct and complete behavior while still
only using a single socket; that is, to be usable for all kinds of multicast
traffic, to support server and client behavior at the same time, and to work
correctly even when multiple IPv6 and IPv4 (using V4MAPPED addresses)
interfaces are present, and any of the interfaces has multiple addresses.

This requires using a plethorea of standardized but not necessarily widely
ported features: ``AI_V4MAPPED`` to support IPv4 without resorting to less
standardized mechanisms for later options, ``IPV6_RECVPKTINFO`` to determine
incoming packages' destination addresses (was it multicast) and to return
packages from the same address, ``IPV6_RECVERR`` to receive ICMP errors even on
sockets that are not connected, ``IPV6_JOIN_GROUP`` for multicast membership
management, and ``recvmsg`` and ``MSG_ERRQUEUE`` to obtain the data configured
with the above options.

There are, if at all, only little attempts made to fall back to a
kind-of-correct or limited-functionality behavior if these options are
unavailable, for the resulting code would be hard to maintain ("``ifdef``
hell") or would cause odd bugs at users (eg. servers that stop working when an
additional IPv6 address gets assigned). If the module does not work for you,
and the options can not be added easily to your platform, consider using the
:mod:`.simple6` module instead.
"""

import asyncio
import socket
import ipaddress
import struct
import weakref
from collections import namedtuple

from ..message import Message
from ..numbers import constants
from .. import error
from .. import interfaces
from ..numbers import COAP_PORT
from ..util.asyncio.recvmsg import RecvmsgDatagramProtocol, create_recvmsg_datagram_endpoint
from ..util import hostportjoin, hostportsplit
from ..util import socknumbers

class UDP6EndpointAddress(interfaces.EndpointAddress):
    """Remote address type for :cls:`MessageInterfaceUDP6`. Remote address is
    stored in form of a socket address; local address can be roundtripped by
    opaque pktinfo data.

    >>> interface = type("FakeMessageInterface", (), {})
    >>> local = UDP6EndpointAddress(socket.getaddrinfo('127.0.0.1', 5683, type=socket.SOCK_DGRAM, family=socket.AF_INET6, flags=socket.AI_V4MAPPED)[0][-1], interface)
    >>> local.is_multicast
    False
    >>> local.hostinfo
    '127.0.0.1'
    >>> all_coap_site = UDP6EndpointAddress(socket.getaddrinfo('ff05:0:0:0:0:0:0:fd', 1234, type=socket.SOCK_DGRAM, family=socket.AF_INET6)[0][-1], interface)
    >>> all_coap_site.is_multicast
    True
    >>> all_coap_site.hostinfo
    '[ff05::fd]:1234'
    >>> all_coap4 = UDP6EndpointAddress(socket.getaddrinfo('224.0.1.187', 5683, type=socket.SOCK_DGRAM, family=socket.AF_INET6, flags=socket.AI_V4MAPPED)[0][-1], interface)
    >>> all_coap4.is_multicast
    True
    """

    def __init__(self, sockaddr, interface, *, pktinfo=None):
        self.sockaddr = sockaddr
        self.pktinfo = pktinfo
        self._interface = weakref.ref(interface)

    scheme = 'coap'

    interface = property(lambda self: self._interface())

    def __hash__(self):
        return hash(self.sockaddr)

    def __eq__(self, other):
        return self.sockaddr == other.sockaddr

    def __repr__(self):
        return "<%s %s%s>"%(type(self).__name__, self.hostinfo, " with local address" if self.pktinfo is not None else "")

    @staticmethod
    def _strip_v4mapped(address):
        if address.startswith('::ffff:') and '.' in address:
            return address[7:]
        return address

    def _plainaddress(self):
        """Return the IP adress part of the sockaddr in IPv4 notation if it is
        mapped, otherwise the plain v6 address including the interface
        identifier if set."""

        if self.sockaddr[3] != 0:
            scopepart = "%" + socket.if_indextoname(self.sockaddr[3])
        else:
            scopepart = ""
        if '%' in self.sockaddr[0]:
            # Fix for Python 3.6 and earlier that reported the scope information
            # in the IP literal (3.7 consistently expresses it in the tuple slot 3)
            scopepart = ""
        return self._strip_v4mapped(self.sockaddr[0]) + scopepart

    def _plainaddress_local(self):
        """Like _plainaddress, but on the address in the pktinfo. Unlike
        _plainaddress, this does not contain the interface identifier."""

        addr, interface = struct.Struct("16si").unpack_from(self.pktinfo)

        return self._strip_v4mapped(socket.inet_ntop(socket.AF_INET6, addr))

    @property
    def hostinfo(self):
        port = self.sockaddr[1]
        if port == COAP_PORT:
            port = None

        # plainaddress: don't assume other applications can deal with v4mapped addresses
        return hostportjoin(self._plainaddress(), port)

    @property
    def hostinfo_local(self):
        host = self._plainaddress_local()
        port = self.interface._local_port()
        if port == 0:
            raise ValueError("Local port read before socket has bound itself")
        if port == COAP_PORT:
            port = None
        return hostportjoin(host, port)

    @property
    def uri_base(self):
        return 'coap://' + self.hostinfo

    @property
    def uri_base_local(self):
        return 'coap://' + self.hostinfo_local

    @property
    def is_multicast(self):
        return ipaddress.ip_address(self._plainaddress().split('%', 1)[0]).is_multicast

    @property
    def is_multicast_locally(self):
        return ipaddress.ip_address(self._plainaddress_local()).is_multicast

    def as_response_address(self):
        if not self.is_multicast_locally:
            return self

        # Create a copy without pktinfo, as responses to messages received to
        # multicast addresses can not have their request's destination address
        # as source address
        return type(self)(self.sockaddr, self.interface)


class SockExtendedErr(namedtuple("_SockExtendedErr", "ee_errno ee_origin ee_type ee_code ee_pad ee_info ee_data")):
    _struct = struct.Struct("IbbbbII")
    @classmethod
    def load(cls, data):
        # unpack_from: recvmsg(2) says that more data may follow
        return cls(*cls._struct.unpack_from(data))

class MessageInterfaceUDP6(RecvmsgDatagramProtocol, interfaces.MessageInterface):
    def __init__(self, ctx: interfaces.MessageManager, log, loop):
        self._ctx = ctx
        self.log = log
        self.loop = loop

        self._shutting_down = None #: Future created and used in the .shutdown() method.

        self.ready = asyncio.Future() #: Future that gets fullfilled by connection_made (ie. don't send before this is done; handled by ``create_..._context``

    def _local_port(self):
        # FIXME: either raise an error if this is 0, or send a message to self
        # to force the OS to decide on a port. Right now, this reports wrong
        # results while the first message has not been sent yet.
        return self.transport.get_extra_info('socket').getsockname()[1]

    @classmethod
    async def _create_transport_endpoint(cls, sock, ctx: interfaces.MessageManager, log, loop, multicast=False):
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socknumbers.IPV6_RECVERR, 1)
        # i'm curious why this is required; didn't IPV6_V6ONLY=0 already make
        # it clear that i don't care about the ip version as long as everything looks the same?
        sock.setsockopt(socket.IPPROTO_IP, socknumbers.IP_RECVERR, 1)

        if multicast:
            # FIXME this all registers only for one interface, doesn't it?
            s = struct.pack('4s4si',
                    socket.inet_aton(constants.MCAST_IPV4_ALLCOAPNODES),
                    socket.inet_aton("0.0.0.0"), 0)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, s)
            except OSError:
                log.warning("Could not join IPv4 multicast group; possibly, there is no network connection available.")
            for a in constants.MCAST_IPV6_ALL:
                s = struct.pack('16si',
                        socket.inet_pton(socket.AF_INET6, a),
                        0)
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6,
                            socket.IPV6_JOIN_GROUP, s)
                except OSError:
                    log.warning("Could not join IPv6 multicast group; possibly, there is no network connection available.")

        transport, protocol = await create_recvmsg_datagram_endpoint(loop,
                lambda: cls(ctx, log=log, loop=loop),
                sock=sock)

        await protocol.ready

        return protocol

    @classmethod
    async def create_client_transport_endpoint(cls, ctx: interfaces.MessageManager, log, loop):
        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        return await cls._create_transport_endpoint(sock, ctx, log, loop, multicast=False)

    @classmethod
    async def create_server_transport_endpoint(cls, ctx: interfaces.MessageManager, log, loop, bind):
        bind = bind or ('::', None)
        bind = (bind[0], bind[1] or COAP_PORT)

        # The later bind() does most of what getaddr info usually does
        # (including resolving names), but is missing out subtly: It does not
        # populate the zone identifier of an IPv6 address, making it impossible
        # without a getaddrinfo (or manual mapping of the name to a number) to
        # bind to a specific link-local interface
        try:
            bind = await loop.getaddrinfo(
                bind[0],
                bind[1],
                family=socket.AF_INET6,
                type=socket.SOCK_DGRAM,
                flags=socket.AI_V4MAPPED,
                )
        except socket.gaierror:
            raise error.ResolutionError("No local bindable address found for %s" % bind[0])
        assert bind, "getaddrinfo returned zero-length list rather than erring out"
        (*_, bind), *additional = bind
        if additional:
            log.warning("Multiple addresses to bind to, ")

        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        # FIXME: SO_REUSEPORT should be safer when available (no port hijacking), and the test suite should work with it just as well (even without). why doesn't it?
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(bind)

        return (await cls._create_transport_endpoint(sock, ctx, log, loop, multicast=True))

    async def shutdown(self):
        self._shutting_down = asyncio.Future()

        self.transport.close()

        await self._shutting_down

        del self._ctx

    def send(self, message):
        ancdata = []
        if message.remote.pktinfo is not None:
            ancdata.append((socket.IPPROTO_IPV6, socket.IPV6_PKTINFO,
                message.remote.pktinfo))
        self.transport.sendmsg(message.encode(), ancdata, 0, message.remote.sockaddr)

    async def recognize_remote(self, remote):
        return isinstance(remote, UDP6EndpointAddress) and \
                remote.interface == self

    async def determine_remote(self, request):
        if request.requested_scheme not in ('coap', None):
            return None

        ## @TODO this is very rudimentary; happy-eyeballs or
        # similar could be employed.

        if request.unresolved_remote is not None:
            host, port = hostportsplit(request.unresolved_remote)
            port = port or COAP_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAP_PORT
        else:
            raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

        try:
            own_sock = self.transport.get_extra_info('socket')
            addrinfo = await self.loop.getaddrinfo(
                host,
                port,
                family=own_sock.family,
                type=0, # Not setting the sock's proto as that fails up to
                        # Python 3.6; setting that would make debugging around
                        # here less confusing but otherwise has no effect
                        # (unless maybe very exotic protocols show up).
                proto=own_sock.proto,
                flags=socket.AI_V4MAPPED,
                )
        except socket.gaierror:
            raise error.ResolutionError("No address information found for requests to %r" % host)
        return UDP6EndpointAddress(addrinfo[0][-1], self)

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
            message = Message.decode(data, UDP6EndpointAddress(address, self, pktinfo=pktinfo))
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s"%(address,))
            return

        self._ctx.dispatch_message(message)

    def datagram_errqueue_received(self, data, ancdata, flags, address):
        assert flags == socknumbers.MSG_ERRQUEUE
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
        remote = UDP6EndpointAddress(address, self, pktinfo=pktinfo)

        # not trying to decode a message from data -- that works for
        # "connection refused", doesn't work for "no route to host", and
        # anyway, when an icmp error comes back, everything pending from that
        # port should err out.

        self._ctx.dispatch_error(errno, remote)

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
