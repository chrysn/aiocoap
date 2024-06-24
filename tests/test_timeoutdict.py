# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio

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
