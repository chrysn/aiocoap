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

# Re-exporting because aiocoap.transports.ws otherwise has a hard time getting
# the import right
from . import asyncio as asyncio, exceptions as exceptions


async def connect(
    uri, subprotocols=None, ping_interval=20, ssl=None
) -> asyncio.connection.Connection:
    from pyodide.ffi.wrappers import add_event_listener
    from js import WebSocket

    if ssl is not None:
        raise ValueError("SSL can not be configured within the browser WebSocket API")

    socket = WebSocket.new(uri, subprotocols)

    # Ignoring ping_interval: We can't tell what the browser does, and it may
    # be right nor not.

    proto = asyncio.client.ClientConnection(socket)

    add_event_listener(
        socket, "open", lambda e, q=proto._queue: q.put_nowait(("open", e))
    )
    add_event_listener(socket, "message", proto.on_message)
    add_event_listener(socket, "error", proto.on_error)
    add_event_listener(socket, "close", proto.on_close)
    (etype, event) = await proto._queue.get()
    if etype != "open":
        raise exceptions.WebSocketException("Failed to connect")
    proto.open = True

    return proto
