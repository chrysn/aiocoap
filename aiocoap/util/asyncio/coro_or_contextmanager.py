# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import functools

class AwaitOrAenter:
    """Helper to wrap around coroutines to make them usable either with
    ``await c`` (possibly later with an asynchronous context manager)
    or with ``async with c as ...:`` without the extra await."""

    def __init__(self, coro):
        self.__coro = coro

    def __await__(self):
        return self.__coro.__await__()

    async def __aenter__(self):
        self.__managed = await self.__coro
        return await self.__managed.__aenter__()

    async def __aexit__(self, exc_type, exc_value, traceback):
        return await self.__managed.__aexit__(exc_type, exc_value, traceback)

    @classmethod
    def decorate(cls, coroutine):
        @functools.wraps(coroutine)
        def decorated(*args, **kwargs):
            coro = coroutine(*args, **kwargs)
            return cls(coro)
        return decorated
