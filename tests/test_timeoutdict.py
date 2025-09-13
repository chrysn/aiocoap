# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
import unittest

from aiocoap.util.asyncio.timeoutdict import TimeoutDict


class TestTimeoutDict(unittest.IsolatedAsyncioTestCase):
    async def test_presence_and_absence(self):
        timeout = 0.2
        d = TimeoutDict(timeout)
        d["k"] = "v"
        await asyncio.sleep(timeout / 2)

        assert d["k"] == "v"

        await asyncio.sleep(timeout * 2.5)
        self.assertRaises(KeyError, lambda: d["k"])
