# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module provides a slimmed-down replacement of the websockets_ module
(that regularly powers :mod:`aiocoap.transports.ws`) -- but implemented through
pyodide_'s JavaScript adapter towards the WebSocket module of the hosting
browser. It aims to be a drop-in replacement that provides the parts that can
be implemented in the browser, and to provide practical errors on the used
entry points. It will not go out of its way to mimick every aspect of the
websockets module, but restrain itself to what ``.ws`` needs.

**Future developement:** The module can probably be extended to cover all the
implementable functionality of websockets, and provide meaningful errors on all
its items. When that happens, it should be split out of aiocoap.

.. _websockets: https://websockets.readthedocs.io/
.. _pyodide: https://pyodide.org/
"""

import asyncio

import js
from pyodide.ffi.wrappers import add_event_listener

class WebSocketCommonProtocol:
    pass

class WebSocketClientProtocol(WebSocketCommonProtocol):
    def __init__(self, socket):
        # Note that this is an under-implemented constructor -- the real thing
        # is in `connect()` which is async enough to do more.

        self._socket = socket
        # FIXME: This is a workaround for WebSockets' shortcomings, while
        # WebSocketStreams are not deployed (see
        # https://developer.chrome.com/articles/websocketstream/ for details)

        self._queue = asyncio.Queue()

        # The initial setting doesn't matter too much because we're not handing
        # it out before setting this to True ... still feels cleaner this way.
        self.open = False

    async def recv(self):
        (etype, event) = await self._queue.get()
        if etype == "message":
            if isinstance(event.data, str):
                # FIXME: Test this
                return event.data
            return bytes((await event.data.arrayBuffer()).to_py())
        elif etype == "close":
            raise exceptions.ConnectionClosed()
        elif etype == "error":
            raise exceptions.WebSocketException("Connection error")
        else:
            raise RuntimeError("Unknown event in queue")

    async def send(self, msg):
        blob = js.Blob.new([js.Uint8Array.new(msg)])
        self._socket.send(blob)

    # FIXME: It'd be preferable if we could make this an unassigned property
    # that'd raise if anybody tried to access it (for neither do we know the
    # value, nor could anything useful be done with it), but as things are,
    # we'll have to rely on all users' sensibilities to not send around
    # addresses that are not globally usable. (The port, indicating the default
    # port, is an outright lie, though.)
    local_address = ("localhost", None)

    def on_message(self, event):
        self._queue.put_nowait(("message", event))

    def on_error(self, event):
        self.open = False
        self._queue.put_nowait(("error", event))

    def on_close(self, event):
        self.open = False
        self._queue.put_nowait(("close", event))

async def connect(uri, subprotocols=None, ping_interval=20, ssl=None) -> WebSocketClientProtocol:
    if ssl is not None:
        raise ValueError("SSL can not be configured within the browser WebSocket API")

    socket = js.WebSocket.new(uri, subprotocols)

    # Ignoring ping_interval: We can't tell what the browser does, and it may
    # be right nor not.

    proto = WebSocketClientProtocol(socket)

    add_event_listener(socket, "open", lambda e, q=proto._queue: q.put_nowait(("open", e)))
    add_event_listener(socket, "message", proto.on_message)
    add_event_listener(socket, "error", proto.on_error)
    add_event_listener(socket, "close", proto.on_close)
    (etype, event) = await proto._queue.get()
    if etype != "open":
        raise exceptions.WebSocketException("Failed to connect")
    proto.open = True

    return proto

class exceptions:
    """A class that is a good-enough approximation of ``websockets.exceptions``
    to get away with a single file implementing pyodide_websockets."""
    class WebSocketException(Exception):
        pass

    class ConnectionClosed(WebSocketException):
        pass

# Mocks required by the aiocoap.transports.ws module expecting a full implementation

class WebSocketServerProtocol:
    def __init__(self, *args, **kwargs):
        raise RuntimeError("Web sockets in web browsers can not be used as servers")

WebSocketServer = WebSocketServerProtocol

def serve(*args, **kwargs):
    WebSocketServer()
