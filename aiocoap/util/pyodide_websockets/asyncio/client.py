# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
from .connection import Connection
from .. import exceptions


class ClientConnection(Connection):
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
        from js import Blob, Uint8Array

        blob = Blob.new([Uint8Array.new(msg)])
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
