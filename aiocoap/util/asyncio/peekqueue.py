# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

class PeekQueue:
    """Queue with a an asynchronous .peek() function.

    This is not implemented in terms of inheritance because it would depend on
    the implementation details of PriorityQueue.put(self, (1, item)) being
    itself implemented in terms of calling self.put_nowait."""

    def __init__(self, *args, **kwargs):
        self._inner = asyncio.PriorityQueue(*args, **kwargs)

    async def put(self, item):
        await self._inner.put((1, item))

    def put_nowait(self, item):
        self._inner.put_nowait((1, item))

    async def peek(self):
        oldprio, first = await self._inner.get()
        self._inner.put_nowait((0, first))
        return first

    async def get(self):
        priority, first = await self._inner.get()
        return first

    def get_nowait(self):
        priority, first = self._inner.get_nowait()
        return first
