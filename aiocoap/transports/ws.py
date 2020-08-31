# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from typing import Dict, List, Optional
from collections import namedtuple
import asyncio
import http

from aiocoap import Message, interfaces, ABORT, util
from aiocoap.transports import rfc8323common

import websockets

def _decode_message(data: bytes) -> Message:
    codeoffset = 1
    tokenoffset = 2

    tkl = data[0]
    if tkl > 8:
        raise error.UnparsableMessage("Overly long token")
    code = data[codeoffset]
    token = data[tokenoffset:tokenoffset + tkl]

    msg = Message(code=code, token=token)

    msg.payload = msg.opt.decode(data[tokenoffset + tkl:])

    return msg

def _serialize(msg: Message) -> bytes:
    tkl = len(msg.token)
    if tkl > 8:
        raise ValueError("Overly long token")

    data = [
            bytes((tkl, msg.code,)),
            msg.token,
            msg.opt.encode(),
            ]
    if msg.payload:
        data += [b'\xff', msg.payload]

    return b"".join(data)

PoolKey = namedtuple("PoolKey", ("scheme", "host", "port"))

class WSRemote(rfc8323common.RFC8323Remote, interfaces.EndpointAddress):
    _connection: websockets.WebSocketCommonProtocol
    _key: PoolKey

    def __init__(self, connection, loop, log, *, local_hostinfo=None, remote_hostinfo=None):
        super().__init__()
        self._connection = connection
        self.loop = loop
        self.log = log

        self._is_server = isinstance(connection, websockets.WebSocketServerProtocol)

        if local_hostinfo is None:
            self._local_hostinfo = self._connection.local_address[:2]
        else:
            self._local_hostinfo = local_hostinfo
        if remote_hostinfo is None:
            self._remote_hostinfo = self._connection.remote_address[:2]
        else:
            self._remote_hostinfo = remote_hostinfo

    @property
    def scheme(self):
        return 'coaps+ws' if self._connection.secure else 'coap+ws'

    # Necessary for RFC8323Remote

    def _abort_with(self, msg, *, close_code=1002):
        # Like _send_message, this may take actual time -- but unlike there,
        # there's no need to regulate back-pressure
        self.loop.create_task(self._abort_with_waiting(msg, close_code=close_code))

    # Unlike _send_message, this is pulled out of the the _abort_with function
    # as it's also used in _run_recv_loop
    async def _abort_with_waiting(self, msg, *, close_code):
        self.log.debug("Aborting with message: %r", msg)
        try:
            await message.remote._connection.send(_serialize(message))
        except Exception as e:
            self.log.error("Sending to a WebSocket should not raise errors", exc_info=e)
        self._connection.close(code=close_code)
        await self._connection.close_wait()

    def _send_message(self, msg):
        # FIXME overhaul back-pressure model
        async def send():
            self.log.debug("Sending message: %r", msg)
            try:
                await self._connection.send(_serialize(msg))
            except Exception as e:
                self.log.error("Sending to a WebSocket should not raise errors", exc_info=e)
        self.loop.create_task(send())

class WSPool(interfaces.TokenInterface):
    _pool: Dict[PoolKey, WSRemote]

    _outgoing_starting: Dict[PoolKey, asyncio.Task]
    # Channel into which an _outgoing_starting item is fed to enter the main task
    _startup_complete: asyncio.Future

    _task: asyncio.Task
    _servers: List[websockets.WebSocketServer]

    def __init__(self, tman, log, loop):
        self.loop = loop

        self._pool = {}
        self._outgoing_queue = {}
        self._startup_complete = loop.create_future()

        self._servers = []

        self._tokenmanager = tman
        self.log = log

    @classmethod
    async def create_transport(cls, tman: interfaces.TokenManager, log, loop, *, client_credentials, server_bind=None, server_context=None):
        self = cls(tman, log, loop)

        if server_bind:
            host, port = server_bind
            if port is None:
                # FIXME document the odd default
                port = 8683

            server = await websockets.serve(
                    self._new_connection,
                    host, port,
                    subprotocols=['coap'],
                    process_request=self._process_request,
                    ping_interval=None, # "SHOULD NOT be used"
                    ssl=server_context,
                    )
            self._servers.append(server)

        return self

    # Helpers for WebScoket server

    async def _new_connection(self, websocket, path):
        # ignoring path: Already checked in _process_request

        local_hostinfo = util.hostportsplit(websocket.request_headers['Host'])

        remote = WSRemote(websocket, self.loop, self.log, local_hostinfo=local_hostinfo)

        # FIXME deposit socket in outgoing for sending -- or should we? (maybe
        # an incoming one is just reachable over the explicit remote object)

        await self._run_recv_loop(remote)

    @staticmethod
    async def _process_request(path, request_headers):
        if path != '/.well-known/coap':
            return (http.HTTPStatus.NOT_FOUND, [], b"")
        # Continue with WebSockets
        return None

    # Implementation of TokenInterface

    async def fill_or_recognize_remote(self, message):
        if isinstance(message.remote, WSRemote) and \
                message.remote._pool is self:
            return True

        if message.requested_scheme in ('coap+ws', 'coaps+ws'):
            FAIL # pick one from the pool if present, otherwise enqueue a new one
            return True

        return False

    def send_message(self, message, exchange_monitor=None):
        if message.code.is_response():
            no_response = (message.opt.no_response or 0) & (1 << message.code.class_ - 1) != 0
            if no_response:
                return

        message.opt.no_response = None

        message.remote._send_message(message)

    async def shutdown(self):
        while self._servers:
            # could be parallelized, but what are the chances there'll actually be multiple
            s = self._servers.pop()
            s.close()
            await s.wait_closed()

        # FIXME any handling needed for outgoing connections?

    # Incoming message processing

    async def _run_recv_loop(self, remote):
        remote._send_initial_csm()

        while True:
            try:
                received = await remote._connection.recv()
            except websockets.exceptions.ConnectionClosed as e:
                # FIXME if deposited somewhere, mark that as stale?
                self.log.info("Expressing WebSocket termination '%s' as errno 0", e)
                self._tokenmanager.dispatch_error(0, remote)
                return

            if not isinstance(received, bytes):
                await remote._abort_with_waiting(Message(code=ABORT, payload=b"Text frame received"), close_code=1003)
                return

            try:
                msg = _decode_message(received)
            except error.UnparsableMessage as e:
                await remote._abort_with_waiting(Message(code=ABORT, payload=b"Message parsing error"), close_code=1007)
                return

            msg.remote = remote

            if msg.code.is_signalling():
                remote._process_signaling(msg)
                continue

            if remote._remote_settings is None:
                remote.abort("No CSM received")
                return

            if msg.code.is_response():
                self._tokenmanager.process_response(msg)
                # ignoring the return value; unexpected responses can be the
                # asynchronous result of cancelled observations
            else:
                self._tokenmanager.process_request(msg)
