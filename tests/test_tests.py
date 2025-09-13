# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Test for the test infrastructure itself

… which is sadly complex enough to need it"""

import asyncio
import os

from .fixtures import IsolatedAsyncioTestCase


class TestRightRunner(IsolatedAsyncioTestCase):
    async def test_right_runner(self):
        """Are we really running on the selected event loop?

        (loop_factory gets assigned, but there's too much that can go wrong
        with this not to test it)"""

        if os.environ.get("AIOCOAP_TESTS_LOOP", None) == "uvloop":
            assert "uvloop" in str(type(asyncio.get_event_loop()))
        elif os.environ.get("AIOCOAP_TESTS_LOOP", None) == "glib":
            assert "GLib" in str(type(asyncio.get_event_loop()))
        else:
            assert "<class 'asyncio." in str(type(asyncio.get_event_loop()))
