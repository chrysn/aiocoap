# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

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
