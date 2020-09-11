# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import socket

from aiocoap.transports import rfc8323common
from aiocoap import interfaces, optiontypes, error, util
from aiocoap import COAP_PORT, Message
from aiocoap.numbers.codes import ABORT
from aiocoap import defaults

def _extract_message_size(data: bytes):
    """Read out the full length of a CoAP messsage represented by data.

    Returns None if data is too short to read the (full) length.

    The number returned is the number of bytes that has to be read into data to
    start reading the next message; it consists of a constant term, the token
    length and the extended length of options-plus-payload."""

    if not data:
        return None

    l = data[0] >> 4
    tokenoffset = 2
    tkl = data[0] & 0x0f

    if l >= 13:
        if l == 13:
            extlen = 1
            offset = 13
        elif l == 14:
            extlen = 2
            offset = 269
        else:
            extlen = 4
            offset = 65805
        if len(data) < extlen + 1:
            return None
        tokenoffset = 2 + extlen
        l = int.from_bytes(data[1:1 + extlen], "big") + offset
    return tokenoffset, tkl, l

def _decode_message(data: bytes) -> Message:
    tokenoffset, tkl, _ = _extract_message_size(data)
    if tkl > 8:
        raise error.UnparsableMessage("Overly long token")
    code = data[tokenoffset - 1]
    token = data[tokenoffset:tokenoffset + tkl]

    msg = Message(code=code, token=token)

    msg.payload = msg.opt.decode(data[tokenoffset + tkl:])

    return msg

def _encode_length(l: int):
    if l < 13:
        return (l, b"")
    elif l < 269:
        return (13, (l - 13).to_bytes(1, 'big'))
    elif l < 65805:
        return (14, (l - 269).to_bytes(2, 'big'))
    else:
        return (15, (l - 65805).to_bytes(4, 'big'))

def _serialize(msg: Message) -> bytes:
    data = [msg.opt.encode()]
    if msg.payload:
        data += [b'\xff', msg.payload]
    data = b"".join(data)
    l, extlen = _encode_length(len(data))

    tkl = len(msg.token)
    if tkl > 8:
        raise ValueError("Overly long token")

    return b"".join((
            bytes(((l << 4) | tkl,)),
            extlen,
            bytes((msg.code,)),
            msg.token,
            data
            ))

class TcpConnection(asyncio.Protocol, rfc8323common.RFC8323Remote, interfaces.EndpointAddress):
    # currently, both the protocol and the EndpointAddress are the same object.
    # if, at a later point in time, the keepaliving of TCP connections should
    # depend on whether the library user still keeps a usable address around,
    # those functions could be split.

    def __init__(self, ctx, log, loop, *, is_server):
        super().__init__()
        self._ctx = ctx
        self.log = log
        self.loop = loop

        self._spool = b""

        self._remote_settings = None

        self._transport = None
        self._local_is_server = is_server

    @property
    def scheme(self):
        return self._ctx._scheme

    def _send_message(self, msg: Message):
        self.log.debug("Sending message: %r", msg)
        self._transport.write(_serialize(msg))

    def _abort_with(self, abort_msg):
        if self._transport is not None:
            self._send_message(abort_msg)
            self._transport.close()
        else:
            # FIXME: find out how this happens; i've only seen it after nmap
            # runs against an aiocoap server and then shutting it down.
            # "poisoning" the object to make sure this can not be exploited to
            # bypass the server shutdown.
            self._ctx = None

    # implementing asyncio.Protocol

    def connection_made(self, transport):
        self._transport = transport

        ssl_object = transport.get_extra_info('ssl_object')
        if ssl_object is not None:
            server_name = getattr(ssl_object, "indicated_server_name", None)
        else:
            server_name = None

        # `host` already contains the interface identifier, so throwing away
        # scope and interface identifier
        self._local_hostinfo = transport.get_extra_info('sockname')[:2]
        self._remote_hostinfo = transport.get_extra_info('peername')[:2]

        def none_default_port(sockname):
            return (sockname[0], None if sockname[1] == self._ctx._default_port else sockname[1])
        self._local_hostinfo = none_default_port(self._local_hostinfo)
        self._remote_hostinfo = none_default_port(self._remote_hostinfo)

        # SNI information available
        if server_name is not None:
            if self._local_is_server:
                self._local_hostinfo = (server_name, self._local_hostinfo[1])
            else:
                self._remote_hostinfo = (server_name, self._remote_hostinfo[1])

        self._send_initial_csm()

    def connection_lost(self, exc):
        # FIXME react meaningfully:
        # * send event through pool so it can propagate the error to all
        #   requests on the same remote
        # * mark the address as erroneous so it won't be recognized by
        #   fill_or_recognize_remote

        self._ctx._dispatch_error(self, exc)

    def data_received(self, data):
        # A rope would be more efficient here, but the expected case is that
        # _spool is b"" and spool gets emptied soon -- most messages will just
        # fit in a single TCP package and not be nagled together.
        #
        # (If this does become a bottleneck, say self._spool = SomeRope(b"")
        # and barely change anything else).

        self._spool += data

        while True:
            msglen = _extract_message_size(self._spool)
            if msglen is None:
                break
            msglen = sum(msglen)
            if msglen > self._my_max_message_size:
                self.abort("Overly large message announced")
                return

            if msglen > len(self._spool):
                break

            msg = self._spool[:msglen]
            try:
                msg = _decode_message(msg)
            except error.UnparsableMessage:
                self.abort("Failed to parse message")
                return
            msg.remote = self

            self.log.debug("Received message: %r", msg)

            self._spool = self._spool[msglen:]

            if msg.code.is_signalling():
                self._process_signaling(msg)
                continue

            if self._remote_settings is None:
                self.abort("No CSM received")
                return

            self._ctx._dispatch_incoming(self, msg)

    def eof_received(self):
        # FIXME: as with connection_lost, but less noisy if announced
        # FIXME: return true and initiate own shutdown if that is what CoAP prescribes
        pass

    def pause_writing(self):
        # FIXME: do something ;-)
        pass

    def resume_writing(self):
        # FIXME: do something ;-)
        pass

class _TCPPooling:
    # implementing TokenInterface

    def send_message(self, message, messageerror_monitor):
        # Ignoring messageerror_monitor: CoAP over reliable transports has no
        # way of indicating that a particular message was bad, it always shuts
        # down the complete connection

        if message.code.is_response():
            no_response = (message.opt.no_response or 0) & (1 << message.code.class_ - 1) != 0
            if no_response:
                return

        message.opt.no_response = None

        message.remote._send_message(message)

    # used by the TcpConnection instances

    def _dispatch_incoming(self, connection, msg):
        if msg.code == 0:
            pass

        if msg.code.is_response():
            self._tokenmanager.process_response(msg)
            # ignoring the return value; unexpected responses can be the
            # asynchronous result of cancelled observations
        else:
            self._tokenmanager.process_request(msg)

    def _dispatch_error(self, connection, exc):
        self._evict_from_pool(connection)

        if self._tokenmanager is None:
            if exc is not None:
                self.log.warning("Ignoring late error during shutdown: %s", exc)
            else:
                # it's just a regular connection loss, that's to be expected during shutdown
                pass
            return

        if isinstance(exc, OSError):
            self._tokenmanager.dispatch_error(exc.errno, connection)
        else:
            self.log.info("Expressing incoming exception %r as errno 0", exc)
            self._tokenmanager.dispatch_error(0, connection)

    # for diverting behavior of _TLSMixIn
    _scheme = 'coap+tcp'
    _default_port = COAP_PORT

class TCPServer(_TCPPooling, interfaces.TokenInterface):
    def __init__(self):
        self._pool = set()

    @classmethod
    async def create_server(cls, bind, tman: interfaces.TokenManager, log, loop, *, _server_context=None):
        self = cls()
        self._tokenmanager = tman
        self.log = log
        #self.loop = loop

        bind = bind or ('::', None)
        bind = (bind[0], bind[1] + (self._default_port - COAP_PORT) if bind[1] else self._default_port)

        def new_connection():
            c = TcpConnection(self, log, loop, is_server=True)
            self._pool.add(c)
            return c

        try:
            server = await loop.create_server(new_connection, bind[0], bind[1],
                    ssl=_server_context, reuse_port=defaults.has_reuse_port())
        except socket.gaierror:
            raise error.ResolutionError("No local bindable address found for %s" % bind[0])
        self.server = server

        return self

    def _evict_from_pool(self, connection):
        self._pool.remove(connection)

    # implementing TokenInterface

    async def fill_or_recognize_remote(self, message):
        if message.remote is not None \
                and isinstance(message.remote, TcpConnection) \
                and message.remote._ctx is self:
            return True

        return False

    async def shutdown(self):
        self.server.close()
        for c in self._pool:
            # FIXME: it would be nicer to release them
            c.abort("Server shutdown")
        await self.server.wait_closed()
        self._tokenmanager = None

class TCPClient(_TCPPooling, interfaces.TokenInterface):
    def __init__(self):
        self._pool = {} # (host, port) -> connection
        # note that connections are filed by host name, so different names for
        # the same address might end up with different connections, which is
        # probably okay for TCP, and crucial for later work with TLS.

    async def _spawn_protocol(self, message):
        if message.unresolved_remote is None:
            host = message.opt.uri_host
            port = message.opt.uri_port or self._default_port
            if host is None:
                raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")
        else:
            host, port = util.hostportsplit(message.unresolved_remote)
            port = port or self._default_port

        if (host, port) in self._pool:
            return self._pool[(host, port)]

        try:
            _, protocol = await self.loop.create_connection(
                    lambda: TcpConnection(self, self.log, self.loop,
                        is_server=False),
                    host, port,
                    ssl=self._ssl_context_factory(message.unresolved_remote))
        except socket.gaierror:
            raise error.ResolutionError("No address information found for requests to %r" % host)
        except OSError:
            raise error.NetworkError("Connection failed to %r" % host)

        self._pool[(host, port)] = protocol

        return protocol

    # for diverting behavior of TLSClient
    def _ssl_context_factory(self, hostinfo):
        return None

    def _evict_from_pool(self, connection):
        keys = []
        for k, p in self._pool.items():
            if p is connection:
                keys.append(k)
        # should really be zero or one
        for k in keys:
            self._pool.pop(k)

    @classmethod
    async def create_client_transport(cls, tman: interfaces.TokenManager, log, loop, credentials=None):
        # this is not actually asynchronous, and even though the interface
        # between the context and the creation of interfaces is not fully
        # standardized, this stays in the other inferfaces' style.
        self = cls()
        self._tokenmanager = tman
        self.log = log
        self.loop = loop
        # used by the TLS variant; FIXME not well thought through
        self.credentials = credentials

        return self

    # implementing TokenInterface

    async def fill_or_recognize_remote(self, message):
        if message.remote is not None \
                and isinstance(message.remote, TcpConnection) \
                and message.remote._ctx is self:
            return True

        if message.requested_scheme == self._scheme:
            # FIXME: This could pool outgoing connections.
            # (Checking if an incoming connection is a pool candidate is
            # probably overkill because even if a URI can be constructed from a
            # ephemeral client port, nobody but us can use it, and we can just
            # set .remote).
            message.remote = await self._spawn_protocol(message)
            return True

        return False

    async def shutdown(self):
        for c in self._pool.values():
            # FIXME: it would be nicer to release them
            c.abort("Server shutdown")
        del self._tokenmanager
