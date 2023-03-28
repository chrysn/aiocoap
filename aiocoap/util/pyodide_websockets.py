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
        # FIXME: How do we get backpressure into the browser?
        self._recv_queue = asyncio.Queue()
        self._err_queue = asyncio.Queue()
        self._close_future = asyncio.Future()

        # The initial setting doesn't matter too much because we're not handing
        # it out before setting this to True ... still feels cleaner this way.
        self.open = False

    async def recv(self):
        # FIXME: or error, and also handle text case?
        event = await self._recv_queue.get()
        return bytes((await event.data.arrayBuffer()).to_py())

    async def send(self, msg):
        blob = js.Blob.new([js.Uint8Array.new(msg)])
        self._socket.send(blob)

    # FIXME
    local_address = ("::", 1234)

async def connect(uri, subprotocols=None, ping_interval=20, ssl=None) -> WebSocketClientProtocol:
    if ssl is not None:
        raise ValueError("SSL can not be configured within the browser WebSocket API")

    socket = js.WebSocket.new(uri, subprotocols)

    # Ignoring ping_interval: We can't tell what the browser does, and it may
    # be right nor not.

    proto = WebSocketClientProtocol(socket)

    opening = asyncio.Future()
    add_event_listener(socket, "open", lambda e, opening=opening: opening.set_result(e))
    add_event_listener(socket, "message", lambda e, queue=proto._recv_queue: queue.put_nowait(e))
    add_event_listener(socket, "error", lambda e, queue=proto._err_queue: queue.put_nowait(e))
    add_event_listener(socket, "close", lambda e, close=proto._close_future: close.set_result(e))
    # FIXME: or error, or maybe even close?
    await opening
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
