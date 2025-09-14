# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module implements a MessageInterface for UDP based on a variation of
the asyncio DatagramProtocol.

This implementation strives to be correct and complete behavior while still
only using a single socket; that is, to be usable for all kinds of multicast
traffic, to support server and client behavior at the same time, and to work
correctly even when multiple IPv6 and IPv4 (using V4MAPPED style addresses)
interfaces are present, and any of the interfaces has multiple addresses.

This requires using some standardized but not necessarily widely ported
features: ``IPV6_RECVPKTINFO`` to determine
incoming packages' destination addresses (was it multicast) and to return
packages from the same address, ``IPV6_JOIN_GROUP`` for multicast
membership management and ``recvmsg`` to obtain data configured with the above
options. The need for ``AI_V4MAPPED`` and ``AI_ADDRCONFIG`` is not manifest
in the code because the latter on its own is insufficient to enable seamless
interoperability with IPv4+IPv6 servers on IPv4-only hosts; instead,
short-lived sockets are crated to assess which addresses are routable. This
should correctly deal with situations in which a client has an IPv6 ULA
assigned but no route, no matter whether the server advertises global IPv6
addresses or addresses inside that ULA. It can not deal with situations in
which the host has a default IPv6 route, but that route is not actually usable.

To the author's knowledge, there is no standardized mechanism for receiving
ICMP errors in such a setup. On Linux, ``IPV6_RECVERR`` and ``MSG_ERRQUEUE``
are used to receive ICMP errors from the socket; on other platforms, a warning
is emitted that ICMP errors are ignored. Using a :mod:`.simple6` for clients is
recommended for those when working as a client only.

Exceeding for the above error handling, no attempts are made to fall back to a
kind-of-correct or limited-functionality behavior if these options are
unavailable, for the resulting code would be hard to maintain ("``ifdef``
hell") or would cause odd bugs at users (eg. servers that stop working when an
additional IPv6 address gets assigned). If the module does not work for you,
and the options can not be added easily to your platform, consider using the
:mod:`.simple6` module instead.
"""

import asyncio
import contextvars
import errno
import os
import socket
import ipaddress
import struct
import weakref
from collections import namedtuple

from ..message import Message
from ..numbers import constants
from .. import defaults
from .. import error
from .. import interfaces
from ..numbers import COAP_PORT
from ..util.asyncio.recvmsg import (
    RecvmsgDatagramProtocol,
    create_recvmsg_datagram_endpoint,
)
from ..util.asyncio.getaddrinfo_addrconfig import (
    getaddrinfo_routechecked as getaddrinfo,
)
from ..util import hostportjoin, hostportsplit
from ..util import socknumbers

"""The `struct in6_pktinfo` from RFC3542"""
_in6_pktinfo = struct.Struct("16sI")

_ipv6_unspecified = socket.inet_pton(socket.AF_INET6, "::")
_ipv4_unspecified = socket.inet_pton(socket.AF_INET6, "::ffff:0.0.0.0")


class InterfaceOnlyPktinfo(bytes):
    """A thin wrapper over bytes that represent a pktinfo built just to select
    an outgoing interface.

    This must not be treated any different than a regular pktinfo, and is just
    tagged for better debug output. (Ie. if this is replaced everywhere with
    plain `bytes`, things must still work)."""


class UDP6EndpointAddress(interfaces.EndpointAddress):
    """Remote address type for :class:`MessageInterfaceUDP6`. Remote address is
    stored in form of a socket address; local address can be roundtripped by
    opaque pktinfo data.

    For purposes of equality (and thus hashing), the local address is *not*
    checked. Neither is the scopeid that is part of the socket address.

    >>> interface = type("FakeMessageInterface", (), {})
    >>> if1_name = socket.if_indextoname(1)
    >>> local = UDP6EndpointAddress(socket.getaddrinfo('127.0.0.1', 5683, type=socket.SOCK_DGRAM, family=socket.AF_INET6, flags=socket.AI_V4MAPPED)[0][-1], interface)
    >>> local.is_multicast
    False
    >>> local.hostinfo
    '127.0.0.1'
    >>> all_coap_link1 = UDP6EndpointAddress(socket.getaddrinfo('ff02:0:0:0:0:0:0:fd%1', 1234, type=socket.SOCK_DGRAM, family=socket.AF_INET6)[0][-1], interface)
    >>> all_coap_link1.is_multicast
    True
    >>> all_coap_link1.hostinfo == '[ff02::fd%{}]:1234'.format(if1_name)
    True
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

    scheme = "coap"

    interface = property(lambda self: self._interface())

    # Unlike for other remotes, this is settable per instance.
    maximum_block_size_exp = constants.MAX_REGULAR_BLOCK_SIZE_EXP

    def __hash__(self):
        return hash(self.sockaddr[:-1])

    def __eq__(self, other):
        return self.sockaddr[:-1] == other.sockaddr[:-1]

    def __repr__(self):
        return "<%s %s%s>" % (
            type(self).__name__,
            self.hostinfo,
            " (locally %s)" % self._repr_pktinfo() if self.pktinfo is not None else "",
        )

    @staticmethod
    def _strip_v4mapped(address):
        """Turn anything that's a valid input to ipaddress.IPv6Address into a
        user-friendly string that's either an IPv6 or an IPv4 address.

        This also compresses (normalizes) the IPv6 address as a convenient side
        effect."""
        address = ipaddress.IPv6Address(address)
        mapped = address.ipv4_mapped
        if mapped is not None:
            return str(mapped)
        return str(address)

    def _plainaddress(self):
        """Return the IP adress part of the sockaddr in IPv4 notation if it is
        mapped, otherwise the plain v6 address including the interface
        identifier if set."""

        if self.sockaddr[3] != 0:
            try:
                scopepart = "%" + socket.if_indextoname(self.sockaddr[3])
            except Exception:  # could be an OS error, could just be that there is no function of this name, as it is on Android
                scopepart = "%" + str(self.sockaddr[3])
        else:
            scopepart = ""
        if "%" in self.sockaddr[0]:
            # Fix for Python 3.6 and earlier that reported the scope information
            # in the IP literal (3.7 consistently expresses it in the tuple slot 3)
            scopepart = ""
        return self._strip_v4mapped(self.sockaddr[0]) + scopepart

    def _repr_pktinfo(self):
        """What repr(self.pktinfo) would be if that were not a plain untyped bytestring"""
        addr, interface = _in6_pktinfo.unpack_from(self.pktinfo)
        if interface == 0:
            interface = ""
        else:
            try:
                interface = "%" + socket.if_indextoname(interface)
            except Exception as e:
                interface = "%%%d(%s)" % (interface, e)

        return "%s%s" % (self._strip_v4mapped(addr), interface)

    def _plainaddress_local(self):
        """Like _plainaddress, but on the address in the pktinfo. Unlike
        _plainaddress, this does not contain the interface identifier."""

        addr, interface = _in6_pktinfo.unpack_from(self.pktinfo)

        return self._strip_v4mapped(addr)

    @property
    def netif(self):
        """Textual interface identifier of the explicitly configured remote
        interface, or the interface identifier reported in an incoming
        link-local message. None if not set."""
        index = self.sockaddr[3]
        return socket.if_indextoname(index) if index else None

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
        return "coap://" + self.hostinfo

    @property
    def uri_base_local(self):
        return "coap://" + self.hostinfo_local

    @property
    def is_multicast(self):
        return ipaddress.ip_address(self._plainaddress().split("%", 1)[0]).is_multicast

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

    @property
    def blockwise_key(self):
        return (self.sockaddr, self.pktinfo)


class SockExtendedErr(
    namedtuple(
        "_SockExtendedErr", "ee_errno ee_origin ee_type ee_code ee_pad ee_info ee_data"
    )
):
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

        self._shutting_down = (
            None  #: Future created and used in the .shutdown() method.
        )

        self.ready = asyncio.get_running_loop().create_future()  #: Future that gets fullfilled by connection_made (ie. don't send before this is done; handled by ``create_..._context``

        # This is set while a send is underway to determine in the
        # error_received call site whom we were actually sending something to.
        # This is a workaround for the abysmal error handling unconnected
        # sockets have :-/
        #
        # FIXME: Figure out whether aiocoap can at all support a context being
        # used with multiple aiocoap contexts, and if not, raise an error early
        # rather than just-in-case doing extra stuff here.
        self._remote_being_sent_to = contextvars.ContextVar(
            "_remote_being_sent_to", default=None
        )

    def _local_port(self):
        # FIXME: either raise an error if this is 0, or send a message to self
        # to force the OS to decide on a port. Right now, this reports wrong
        # results while the first message has not been sent yet.
        return self.transport.get_extra_info("socket").getsockname()[1]

    @classmethod
    async def _create_transport_endpoint(
        cls, sock, ctx: interfaces.MessageManager, log, loop, multicast=[]
    ):
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socknumbers.IPV6_RECVPKTINFO, 1)
        except NameError:
            raise RuntimeError(
                "RFC3542 PKTINFO flags are unavailable, unable to create a udp6 transport."
            )
        if socknumbers.HAS_RECVERR:
            sock.setsockopt(socket.IPPROTO_IPV6, socknumbers.IPV6_RECVERR, 1)
            # i'm curious why this is required; didn't IPV6_V6ONLY=0 already make
            # it clear that i don't care about the ip version as long as everything looks the same?
            sock.setsockopt(socket.IPPROTO_IP, socknumbers.IP_RECVERR, 1)
        else:
            log.warning(
                "Transport udp6 set up on platform without RECVERR capability. ICMP errors will be ignored."
            )

        for address_string, interface_string in sum(
            map(
                # Expand shortcut of "interface name means default CoAP all-nodes addresses"
                lambda i: [(a, i) for a in constants.MCAST_ALL]
                if isinstance(i, str)
                else [i],
                multicast,
            ),
            [],
        ):
            address = ipaddress.ip_address(address_string)
            interface = socket.if_nametoindex(interface_string)

            if isinstance(address, ipaddress.IPv4Address):
                s = struct.pack(
                    "4s4si", address.packed, socket.inet_aton("0.0.0.0"), interface
                )
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, s)
                except OSError:
                    log.warning("Could not join IPv4 multicast group")

            elif isinstance(address, ipaddress.IPv6Address):
                s = struct.pack("16si", address.packed, interface)
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, s)
                except OSError:
                    log.warning("Could not join IPv6 multicast group")

            else:
                raise RuntimeError("Unknown address format")

        transport, protocol = await create_recvmsg_datagram_endpoint(
            loop, lambda: cls(ctx, log=log, loop=loop), sock=sock
        )

        await protocol.ready

        return protocol

    @classmethod
    async def create_client_transport_endpoint(
        cls, ctx: interfaces.MessageManager, log, loop
    ):
        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        return await cls._create_transport_endpoint(sock, ctx, log, loop)

    @classmethod
    async def create_server_transport_endpoint(
        cls, ctx: interfaces.MessageManager, log, loop, bind, multicast
    ):
        bind = bind or ("::", None)
        # Interpret None as 'default port', but still allow to bind to 0 for
        # servers that want a random port (eg. when the service URLs are
        # advertised out-of-band anyway, or in LwM2M clients)
        bind = (bind[0], COAP_PORT if bind[1] is None else bind[1])

        # The later bind() does most of what getaddr info usually does
        # (including resolving names), but is missing out subtly: It does not
        # populate the zone identifier of an IPv6 address, making it impossible
        # without a getaddrinfo (or manual mapping of the name to a number) to
        # bind to a specific link-local interface
        try:
            addriter = getaddrinfo(
                loop,
                log,
                bind[0],
                bind[1],
            )
            try:
                bind = await addriter.__anext__()
            except StopAsyncIteration:
                raise RuntimeError(
                    "getaddrinfo returned zero-length list rather than erring out"
                )
        except socket.gaierror:
            raise error.ResolutionError(
                "No local bindable address found for %s" % bind[0]
            )

        try:
            additional = await addriter.__anext__()
        except StopAsyncIteration:
            pass
        except Exception as e:
            log.error(
                "Ignoring exception raised when checking for additional addresses that match the bind address",
                exc_info=e,
            )
        else:
            log.warning(
                "Multiple addresses to bind to, only selecting %r and discarding %r and any later",
                bind,
                additional,
            )

        sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        if defaults.has_reuse_port():
            # I doubt that there is any platform that supports RECVPKTINFO but
            # not REUSEPORT, but why take chances.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(bind)

        return await cls._create_transport_endpoint(sock, ctx, log, loop, multicast)

    async def shutdown(self):
        self._shutting_down = asyncio.get_running_loop().create_future()

        self.transport.close()

        await self._shutting_down

        del self._ctx

    def send(self, message):
        ancdata = []
        if message.remote.pktinfo is not None:
            ancdata.append(
                (socket.IPPROTO_IPV6, socknumbers.IPV6_PKTINFO, message.remote.pktinfo)
            )
        assert self._remote_being_sent_to.get(None) is None, (
            "udp6.MessageInterfaceUDP6.send was reentered in a single task"
        )
        self._remote_being_sent_to.set(message.remote)
        try:
            self.transport.sendmsg(
                message.encode(), ancdata, 0, message.remote.sockaddr
            )
        finally:
            self._remote_being_sent_to.set(None)

    async def recognize_remote(self, remote):
        return isinstance(remote, UDP6EndpointAddress) and remote.interface == self

    async def determine_remote(self, request):
        if request.requested_scheme not in ("coap", None):
            return None

        if request.unresolved_remote is not None:
            host, port = hostportsplit(request.unresolved_remote)
            port = port or COAP_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            port = request.opt.uri_port or COAP_PORT
        else:
            raise ValueError(
                "No location found to send message to (neither in .opt.uri_host nor in .remote)"
            )

        # Take aside the zone identifier. While it can pass through getaddrinfo
        # in some situations (eg. 'fe80::1234%eth0' will give 'fe80::1234'
        # scope eth0, and similar for ff02:: addresses), in others (eg. ff05::)
        # it gives 'Name or service not known'.

        if "%" in host:
            host, zone = host.split("%", 1)
            try:
                zone = socket.if_nametoindex(zone)
            except OSError:
                raise error.ResolutionError("Invalid zone identifier %s" % zone)
        else:
            zone = None

        try:
            # Note that this is our special addrinfo that ensures there is a
            # route.
            ip, port, flowinfo, scopeid = await getaddrinfo(
                self.loop,
                self.log,
                host,
                port,
            ).__anext__()
        except socket.gaierror:
            raise error.ResolutionError(
                "No address information found for requests to %r" % host
            )

        if zone is not None:
            # Still trying to preserve the information returned (libc can't do
            # it as described at
            # <https://unix.stackexchange.com/questions/174767/ipv6-zone-id-in-etc-hosts>)
            # in case something sane does come out of that.
            if scopeid != 0 and scopeid != zone:
                self.log.warning(
                    "Resolved address of %s came with zone ID %d whereas explicit ID %d takes precedence",
                    host,
                    scopeid,
                    zone,
                )
            scopeid = zone

        # We could be done here and return UDP6EndpointAddress(the reassembled
        # sockaddr, self), but:
        #
        # Linux (unlike FreeBSD) takes the sockaddr's scope ID only for
        # link-local scopes (as per ipv6(7), and discards it otherwise. It does
        # need the information of the selected interface, though, in order to
        # pick the right outgoing interface. Thus, we provide it in the local
        # portion.

        if scopeid:
            # "Any" does not include "even be it IPv4" -- the underlying family
            # unfortunately needs to be set, or Linux will refuse to send.
            if ipaddress.IPv6Address(ip).ipv4_mapped is None:
                local_source = _ipv6_unspecified
            else:
                local_source = _ipv4_unspecified
            local = InterfaceOnlyPktinfo(_in6_pktinfo.pack(local_source, scopeid))
        else:
            local = None

        sockaddr = ip, port, flowinfo, scopeid
        result = UDP6EndpointAddress(sockaddr, self, pktinfo=local)
        if request.remote.maximum_block_size_exp < result.maximum_block_size_exp:
            result.maximum_block_size_exp = request.remote.maximum_block_size_exp
        return result

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
            if (
                cmsg_level == socket.IPPROTO_IPV6
                and cmsg_type == socknumbers.IPV6_PKTINFO
            ):
                pktinfo = cmsg_data
            else:
                self.log.info(
                    "Received unexpected ancillary data to recvmsg: level %d, type %d, data %r",
                    cmsg_level,
                    cmsg_type,
                    cmsg_data,
                )
        if pktinfo is None:
            self.log.warning(
                "Did not receive requested pktinfo ancdata on message from %s", address
            )
        try:
            message = Message.decode(
                data, UDP6EndpointAddress(address, self, pktinfo=pktinfo)
            )
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s", address)
            return

        try:
            self._ctx.dispatch_message(message)
        except BaseException as exc:
            # Catching here because util.asyncio.recvmsg inherits
            # _SelectorDatagramTransport's bad handling of callback errors;
            # this is the last time we have a log at hand.
            self.log.error(
                "Exception raised through dispatch_message: %s", exc, exc_info=exc
            )
            raise

    def datagram_errqueue_received(self, data, ancdata, flags, address):
        assert flags == socknumbers.MSG_ERRQUEUE, (
            "Received non-error data through the errqueue"
        )
        pktinfo = None
        errno_value = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            assert cmsg_level == socket.IPPROTO_IPV6, (
                "Received non-IPv6 protocol through the errqueue"
            )
            if cmsg_type == socknumbers.IPV6_RECVERR:
                extended_err = SockExtendedErr.load(cmsg_data)
                self.log.debug("Socket error recevied, details: %s", extended_err)
                errno_value = extended_err.ee_errno
            elif (
                cmsg_level == socket.IPPROTO_IPV6
                and cmsg_type == socknumbers.IPV6_PKTINFO
            ):
                pktinfo = cmsg_data
            else:
                self.log.info(
                    "Received unexpected ancillary data to recvmsg errqueue: level %d, type %d, data %r",
                    cmsg_level,
                    cmsg_type,
                    cmsg_data,
                )
        remote = UDP6EndpointAddress(address, self, pktinfo=pktinfo)

        # not trying to decode a message from data -- that works for
        # "connection refused", doesn't work for "no route to host", and
        # anyway, when an icmp error comes back, everything pending from that
        # port should err out.

        try:
            text = os.strerror(errno_value)
            symbol = errno.errorcode.get(errno_value, None)
            symbol = "" if symbol is None else f"{symbol}, "
            self._ctx.dispatch_error(
                OSError(errno_value, f"{text} ({symbol}received through errqueue)"),
                remote,
            )
        except BaseException as exc:
            # Catching here because util.asyncio.recvmsg inherits
            # _SelectorDatagramTransport's bad handling of callback errors;
            # this is the last time we have a log at hand.
            self.log.error(
                "Exception raised through dispatch_error: %s", exc, exc_info=exc
            )
            raise

    def error_received(self, exc):
        """Implementation of the DatagramProtocol interface, called by the transport."""

        remote = self._remote_being_sent_to.get()

        if remote is None:
            self.log.info(
                "Error received in situation with no way to to determine which sending caused the error; this should be accompanied by an error in another code path: %s",
                exc,
            )
            return

        try:
            self._ctx.dispatch_error(exc, remote)
        except BaseException as exc:
            # Catching here because util.asyncio.recvmsg inherits
            # _SelectorDatagramTransport's bad handling of callback errors;
            # this is the last time we have a log at hand.
            self.log.error(
                "Exception raised through dispatch_error: %s", exc, exc_info=exc
            )
            raise

    def connection_lost(self, exc):
        # TODO better error handling -- find out what can cause this at all
        # except for a shutdown
        if exc is not None:
            self.log.error("Connection lost: %s", exc)

        if self._shutting_down is None:
            self.log.error("Connection loss was not expected.")
        else:
            self._shutting_down.set_result(None)
