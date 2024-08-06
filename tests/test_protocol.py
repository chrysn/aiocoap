# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import unittest

from .fixtures import asynctest, no_warnings, WithAsyncLoop, WithLogMonitoring
from . import common

from aiocoap import Context


class TestProtocolSetup(WithLogMonitoring, WithAsyncLoop):
    """Tests that are only concerned with the setup of contexts, and the way
    they can be set up."""

    @no_warnings
    @asynctest
    async def test_empty_setup_shutdown(self):
        ctx = await Context.create_client_context()
        await ctx.shutdown()

    # There is not yet a way to set things up in an async context manager.

    #     @no_warnings
    #     @asynctest
    #     async def test_empty_contextmgr(self):
    #         async with Context.create_client_context():
    #             pass

    # The following tests should be converted to context managers once usable.

    @no_warnings
    @asynctest
    # Workaround for https://github.com/chrysn/aiocoap/issues/321
    @unittest.skipIf(
        hasattr(common, "gbulb"),
        reason="uvloop has unresolved issues with unused contexts",
    )
    async def test_multiple_contexts(self):
        # Not that that'd be a regular thing to do, just checking it *can* be
        # done
        c1 = await Context.create_client_context(loggername="coap-client1")
        c2 = await Context.create_client_context(loggername="coap-client2")
        # None is an acceptable site; binding to a concrete port
        # removes the worries of situations where the default
        # transports can't bind to "any".
        s1 = await Context.create_server_context(
            None, bind=("::1", None), loggername="coap-server"
        )

        await c1.shutdown()
        await s1.shutdown()
        await c2.shutdown()

    @no_warnings
    @asynctest
    async def test_serverports_no_conflict(self):
        # When different ports are used, servers should not get into conflict.
        #
        # (To some extent, that this is so easy is the fault of the weird way
        # the other protocols' ports are set for lack of configurability).
        s1 = await Context.create_server_context(None, bind=("::1", 1234))
        s2 = await Context.create_server_context(None, bind=("::1", None))

        await s1.shutdown()
        await s2.shutdown()
