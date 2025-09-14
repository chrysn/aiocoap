# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""
This moduel implements a TokenInterface for `CoAP over WebSockets`_.

.. _`CoAP over WebSockets`: https://tools.ietf.org/html/rfc8323#section-4

As with CoAP-over-TCP, while the transport distinguishes a connection initiator
("WebSocket (and TCP) client") and a receiver ("WebSocket (and TCP) server"),
both sides can take both roles in CoAP (ie. as a CoAP server and a CoAP
client). As the WebSocket client can not possibly be connected to (even by the
same server -- once the connection is closed, it's gone and even a new one
likely has a different port), aiocoap does not allow expressing their addresses
in URIs (given they wouldn't serve their purpose as URLs and don't provide any
stability either). Requests to a CoAP-over-WS client can be made by assigning
the remote to an outgoing request.

Port choice
-----------

Unlike the other transports, CoAP-over-WS is specified with a privileged port
(port 80) as the default port. This is impractical for aiocoap servers for two
reasons:

    * Unless explicitly configured, aiocoap is typically run as an unprivileged
      user (and has no provisions in place to receive a socket by other means
      than opening it).

    * Where a CoAP-over-WS proxy is run, there is often a "proper" website
      running on the same port on a full HTTP server. That server is usually
      capable of forwarding requests, whereas the ``websockets`` module used by
      aiocoap is in no position to either serve websites nor to proxy to an
      underlying server.

The recommended setup is therefore to run a full web server at port 80, and
configure it to proxy incoming requests for WebSockets at `/.well-known/coap`
to aiocoap's server, which defaults to binding to port 8683.

The port choice of outgoing connections, or the interpretation of the
protocol's default port (ie. the port implied by ``coap+ws://hostname/``) is of
course unaffected by this.

.. warning::

  Due to a shortcoming of aiocoap's way of specifying ports to bind
  to, if a port is explicitly stated to bind to, CoAP-over-WS will bind to that
  port plus 3000 (resulting in the abovementioned 8683 for 5683). If TLS server
  keys are given, the TLS server is launched on the next port after the HTTP
  server (typically 8684).

Using on pyodide_
-----------------

When use  on pyodide_,
instead of using the ``websockets`` module,
a simplified client-only back-end is used,
which utilizes the browser's WebSocket API.

.. _pyodide: https://pyodide.org/
"""

from __future__ import annotations

from typing import Dict, List
from collections import namedtuple
import asyncio
import functools
import http
import weakref

from aiocoap import Message, interfaces, ABORT, util, error
from aiocoap.transports import rfc8323common
from ..credentials import CredentialsMap
from ..defaults import is_pyodide

if not is_pyodide:
    import websockets.asyncio.connection
    import websockets.asyncio.server
else:
    import aiocoap.util.pyodide_websockets as websockets  # type: ignore[no-redef]


def _decode_message(data: bytes) -> Message:
    codeoffset = 1
    tokenoffset = 2

    tkl = data[0]
    if tkl > 8:
        raise error.UnparsableMessage("Overly long token")
    code = data[codeoffset]
    token = data[tokenoffset : tokenoffset + tkl]

    msg = Message(code=code, token=token)

    msg.payload = msg.opt.decode(data[tokenoffset + tkl :])

    return msg


def _serialize(msg: Message) -> bytes:
    tkl = len(msg.token)
    if tkl > 8:
        raise ValueError("Overly long token")

    data = [
        bytes(
            (
                tkl,
                msg.code,
            )
        ),
        msg.token,
        msg.opt.encode(),
    ]
    if msg.payload:
        data += [b"\xff", msg.payload]

    return b"".join(data)


PoolKey = namedtuple("PoolKey", ("scheme", "hostinfo"))


class WSRemote(rfc8323common.RFC8323Remote, interfaces.EndpointAddress):
    _connection: websockets.asyncio.connection.Connection
    # Only used to ensure that remotes are associated to the right pool -- not
    # that there'd be any good reason to have multiple of those.
    _pool: weakref.ReferenceType[WSPool]
    _poolkey: PoolKey

    scheme = None  # Override property -- it's per instance here

    def __init__(
        self,
        pool,
        connection,
        loop,
        log,
        *,
        scheme,
        local_hostinfo=None,
        remote_hostinfo=None,
    ):
        super().__init__()
        self._pool = weakref.ref(pool)
        self._connection = connection
        self.loop = loop
        self.log = log

        self._local_is_server = isinstance(
            connection, websockets.asyncio.server.ServerConnection
        )

        if local_hostinfo is None:
            self._local_hostinfo = self._connection.local_address[:2]
        else:
            self._local_hostinfo = local_hostinfo
        if remote_hostinfo is None:
            self._remote_hostinfo = self._connection.remote_address[:2]
        else:
            self._remote_hostinfo = remote_hostinfo

        self.scheme = scheme

        # Goes both for client and for server ends; on the server end, it
        # ensures that role reversal URIs can be used even when passed as URIs
        # and not as remotes (although that's of course only possible locally).
        self._poolkey = PoolKey(self.scheme, self.hostinfo)

    # Necessary for RFC8323Remote

    def _abort_with(self, msg, *, close_code=1002):
        # Like _send_message, this may take actual time -- but unlike there,
        # there's no need to regulate back-pressure
        self.loop.create_task(
            self._abort_with_waiting(msg, close_code=close_code),
            name="Abortion WebSocket sonnection with %r" % msg,
        )

    # Unlike _send_message, this is pulled out of the the _abort_with function
    # as it's also used in _run_recv_loop
    async def _abort_with_waiting(self, msg, *, close_code):
        self.log.debug("Aborting with message: %r", msg)
        try:
            await self._connection.send(_serialize(msg))
        except Exception as e:
            self.log.error("Sending to a WebSocket should not raise errors", exc_info=e)
        await self._connection.close(code=close_code)

    def _send_message(self, msg):
        # FIXME overhaul back-pressure model
        async def send():
            self.log.debug("Sending message: %r", msg)
            try:
                await self._connection.send(_serialize(msg))
            except Exception as e:
                self.log.error(
                    "Sending to a WebSocket should not raise errors", exc_info=e
                )

        self.loop.create_task(
            send(),
            name="WebSocket sending of %r" % msg,
        )

    async def release(self):
        await super().release()
        try:
            await self._connection.wait_closed()
        except asyncio.CancelledError:
            self.log.warning(
                "Connection %s was not closed by peer in time after release", self
            )


class WSPool(interfaces.TokenInterface):
    _outgoing_starting: Dict[PoolKey, asyncio.Task]
    _pool: Dict[PoolKey, WSRemote]

    _servers: List[websockets.asyncio.server.Server]

    def __init__(self, tman, log, loop) -> None:
        self.loop = loop

        self._pool = {}
        self._outgoing_starting = {}

        self._servers = []

        # See where it is used for documentation, remove when not needed any more
        self._in_shutdown = False

        self._tokenmanager = tman
        self.log = log

        self._client_credentials: CredentialsMap

    @classmethod
    async def create_transport(
        cls,
        tman: interfaces.TokenManager,
        log,
        loop,
        *,
        client_credentials,
        server_bind=None,
        server_context=None,
    ):
        self = cls(tman, log, loop)

        self._client_credentials = client_credentials

        if server_bind:
            host, port = server_bind
            if port is None:
                port = 8683
            elif port != 0:
                # FIXME see module documentation
                port = port + 3000

            server = await websockets.asyncio.server.serve(
                functools.partial(self._new_connection, scheme="coap+ws"),
                host,
                port,
                # Ignoring type: Documentation says strings are OK
                subprotocols=["coap"],  # type: ignore[list-item]
                process_request=self._process_request,
                ping_interval=None,  # "SHOULD NOT be used"
            )
            self._servers.append(server)

            if server_context is not None:
                server = await websockets.asyncio.server.serve(
                    functools.partial(self._new_connection, scheme="coaps+ws"),
                    host,
                    port + 1,
                    # Ignoring type: Documentation says strings are OK
                    subprotocols=["coap"],  # type: ignore[list-item]
                    process_request=self._process_request,
                    ping_interval=None,  # "SHOULD NOT be used"
                    ssl=server_context,
                )
                self._servers.append(server)

        return self

    # Helpers for WebScoket server

    async def _new_connection(self, websocket, path=None, *, scheme):
        # ignoring path: Already checked in _process_request
        #
        # (path is present up to 10.0 and absent in 10.1; keeping it around to
        # stay compatible with different versions).

        hostheader = websocket.request.headers["Host"]
        local_hostinfo = util.hostportsplit(hostheader)

        remote = WSRemote(
            self,
            websocket,
            self.loop,
            self.log,
            scheme=scheme,
            local_hostinfo=local_hostinfo,
        )
        self._pool[remote._poolkey] = remote

        await self._run_recv_loop(remote)

    @staticmethod
    async def _process_request(connection, request):
        path = connection.request.path
        if path != "/.well-known/coap":
            return (http.HTTPStatus.NOT_FOUND, [], b"")
        # Continue with WebSockets
        return None

    # Helpers for WebScoket client

    def _connect(self, key: PoolKey):
        self._outgoing_starting[key] = self.loop.create_task(
            self._connect_task(key),
            name="WebSocket connection opening to %r" % (key,),
        )

    async def _connect_task(self, key: PoolKey):
        try:
            ssl_context = self._client_credentials.ssl_client_context(
                key.scheme, key.hostinfo
            )

            hostinfo_split = util.hostportsplit(key.hostinfo)

            ws_scheme = {"coap+ws": "ws", "coaps+ws": "wss"}[key.scheme]

            if ws_scheme == "ws" and ssl_context is not None:
                raise ValueError(
                    "An SSL context was provided for a remote accessed via a plaintext websockets."
                )
            if ws_scheme == "wss":
                if is_pyodide:
                    if ssl_context is not None:
                        raise ValueError(
                            "The pyodide websocket implementation can't be configured with a non-default context -- connections created in a browser will always use the browser's CA set."
                        )
                else:
                    if ssl_context is None:
                        # Like with TLSClient, we need to pass in a default
                        # context and can't rely on the websocket library to
                        # use a default one when wss is requested (it doesn't)
                        import ssl

                        ssl_context = ssl.create_default_context()

            websocket = await websockets.connect(
                "%s://%s/.well-known/coap" % (ws_scheme, key.hostinfo),
                # Ignoring type: Documentation says strings are OK
                subprotocols=["coap"],  # type: ignore[list-item]
                ping_interval=None,
                ssl=ssl_context,
            )

            remote = WSRemote(
                self,
                websocket,
                self.loop,
                self.log,
                scheme=key.scheme,
                remote_hostinfo=hostinfo_split,
            )
            assert remote._poolkey == key, "Pool key construction is inconsistent"
            self._pool[key] = remote

            self.loop.create_task(
                self._run_recv_loop(remote),
                name="WebSocket receive loop for %r" % (key,),
            )

            return remote
        finally:
            del self._outgoing_starting[key]

    # Implementation of TokenInterface

    async def fill_or_recognize_remote(self, message):
        if isinstance(message.remote, WSRemote) and message.remote._pool() is self:
            return True

        if message.requested_scheme in ("coap+ws", "coaps+ws"):
            key = PoolKey(message.requested_scheme, message.remote.hostinfo)

            if key in self._pool:
                message.remote = self._pool[key]
                # It would have handled the ConnectionClosed on recv and
                # removed itself if it was not live.
                return True

            if key not in self._outgoing_starting:
                self._connect(key)
            # It's a bit unorthodox to wait for an (at least partially)
            # established connection in fill_or_recognize_remote, but it's
            # not completely off off either, and it makes it way easier to
            # not have partially initialized remotes around
            message.remote = await self._outgoing_starting[key]
            return True

        return False

    def send_message(self, message, messageerror_monitor):
        # Ignoring messageerror_monitor: CoAP over reliable transports has no
        # way of indicating that a particular message was bad, it always shuts
        # down the complete connection

        if message.code.is_response():
            no_response = (message.opt.no_response or 0) & (
                1 << message.code.class_ - 1
            ) != 0
            if no_response:
                return

        message.opt.no_response = None

        message.remote._send_message(message)

    async def shutdown(self):
        self._in_shutdown = True
        self.log.debug("Shutting down any connections on %r", self)
        self._tokenmanager = None

        client_shutdowns = [
            asyncio.create_task(
                c.release(),
                name="Close connection %s" % c,
            )
            for c in self._pool.values()
        ]

        server_shutdowns = []
        while self._servers:
            s = self._servers.pop()
            # We could do something like
            # >>> for websocket in s.websockets:
            # >>>     del websocket.logger.extra['websocket']
            # to reduce the reference loops
            # (websocket.logger.extra['websocket'] == websocket), but as the
            # tests actually do run a GC collection once and that gets broken
            # up, it's not worth adding fragilty here
            s.close()
            server_shutdowns.append(
                asyncio.create_task(s.wait_closed(), name="Close server %s" % s),
            )

        # Placing client shutdowns before server shutdowns to give them a
        # chance to send out Abort messages; the .close() method could be more
        # helpful here by stopping new connections but letting us finish off
        # the old ones
        shutdowns = client_shutdowns + server_shutdowns
        if shutdowns:
            # wait is documented to require a non-empty set
            await asyncio.wait(shutdowns)

    # Incoming message processing

    async def _run_recv_loop(self, remote):
        remote._send_initial_csm()

        while True:
            try:
                received = await remote._connection.recv()
            except websockets.exceptions.ConnectionClosed:
                # This check is purely needed to silence the warning printed
                # from tokenmanager, "Internal shutdown sequence msismatch:
                # error dispatched through tokenmanager after shutdown" -- and
                # is a symptom of https://github.com/chrysn/aiocoap/issues/284
                # and of the odd circumstance that we can't easily cancel the
                # _run_recv_loop tasks (as we should while that issue is
                # unresolved) in the shutdown handler.
                if not self._in_shutdown:
                    # FIXME if deposited somewhere, mark that as stale?
                    self._tokenmanager.dispatch_error(
                        error.RemoteServerShutdown("Peer closed connection"), remote
                    )
                return

            if not isinstance(received, bytes):
                await remote._abort_with_waiting(
                    Message(code=ABORT, payload=b"Text frame received"), close_code=1003
                )
                return

            try:
                msg = _decode_message(received)
            except error.UnparsableMessage:
                await remote._abort_with_waiting(
                    Message(code=ABORT, payload=b"Message parsing error"),
                    close_code=1007,
                )
                return

            msg.remote = remote

            if msg.code.is_signalling():
                try:
                    remote._process_signaling(msg)
                except rfc8323common.CloseConnection as e:
                    self._tokenmanager.dispatch_error(e.args[0], msg.remote)
                    self._pool.pop(remote._poolkey)
                    await remote._connection.close()
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
