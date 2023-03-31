# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
# Copyright (c) 2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# SPDX-License-Identifier: MIT

import asyncio
import unittest

from aiocoap.util.asyncio.timeoutdict import TimeoutDict

from .fixtures import WithAsyncLoop, asynctest

class TestTimeoutDict(WithAsyncLoop):
    @asynctest
    async def test_presence_and_absence(self):
        timeout = 0.2
        d = TimeoutDict(timeout)
        d["k"] = "v"
        await asyncio.sleep(timeout / 2)

        assert d["k"] == "v"

        await asyncio.sleep(timeout * 2.5)
        self.assertRaises(KeyError, lambda: d["k"])
