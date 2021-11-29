# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from .fixtures import asynctest, no_warnings, WithAsyncLoop, WithLogMonitoring

from aiocoap import Context

class TestProtocolSetup(WithLogMonitoring, WithAsyncLoop):
    """Tests that are only concerned with the setup of contexts, and the way
    they can be set up."""

    @no_warnings
    @asynctest
    async def test_empty_setup_shutdown(self):
        ctx = await Context.create_client_context()
        await ctx.shutdown()

    @no_warnings
    @asynctest
    async def test_empty_contextmgr(self):
        async with Context.create_client_context():
            pass

    @no_warnings
    @asynctest
    async def test_multiple_contexts(self):
        # Not that that'd be a regular thing to do, just checking it *can* be
        # done
        async with Context.create_client_context():
            async with Context.create_client_context():
                # None is an acceptable site; binding to a concrete port
                # removes the worries of situations where the default
                # transports can't bind to "any".
                async with Context.create_server_context(None, bind=("::1", None)):
                    pass

    @no_warnings
    @asynctest
    async def test_serverports_no_conflict(self):
        # When different ports are used, servers should not get into conflict.
        #
        # (To some extent, that this is so easy is the fault of the weird way
        # the other protocols' ports are set for lack of configurability).
        async with Context.create_server_context(None, bind=("::1", 1234)):
            async with Context.create_server_context(None, bind=("::1", None)):
                pass
