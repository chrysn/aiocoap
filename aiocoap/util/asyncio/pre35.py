# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

class AsyncGenerator:
    """An object implementing the __aiter__ protocol until `async def / yield`
    can be used in all supported versions"""

    def __init__(self):
        self._queue = asyncio.Queue() #: (data, exception) tuples -- data is valid iff exception is None

    def __aiter__(self):
        return self

    async def __anext__(self):
        data, exception = await self._queue.get()
        if exception is None:
            return data
        else:
            raise exception

    def throw(self, exception):
        self._queue.put_nowait((None, exception))

    def ayield(self, item):
        self._queue.put_nowait((item, None))

    def finish(self):
        self.throw(StopAsyncIteration)
