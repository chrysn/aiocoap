# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import unittest

import aiocoap
from aiocoap import resource

from .test_server import WhoAmI


class RoleReverseAndQueryWhoAmI(resource.Resource):
    context: aiocoap.Context

    async def render_post(self, request):
        counter_request = aiocoap.Message(code=aiocoap.GET, uri_path=["whoami"])
        counter_request.remote = request.remote
        response = await self.context.request(counter_request).response_raising
        # Maybe we should raise a warning but ignore this...
        response.direction = aiocoap.message.Direction.OUTGOING
        # ... like we do with those (just clearing them for the warnings)
        response.mid = None
        response.token = None
        return response


class TestMultitransportRolereversal(unittest.IsolatedAsyncioTestCase):
    """A test family for whether even when multiple transports are active, role
    reversal works as it should."""

    async def test_udp6_multiport(self):
        """Let a client connect to a udp6 multiply bound server, and verify
        that role reversal comes from the right place.

        This is a bit of a funny test because it enforces UDP6 on one side
        while using the defaults on the other."""

        checkme = RoleReverseAndQueryWhoAmI()
        serversite = resource.Site()
        serversite.add_resource(["checkme"], checkme)

        serverctx = await aiocoap.Context.create_server_context(
            serversite,
            transports={
                "udp6": {
                    "bind": ["[::]:5001", "[::]:5002"],
                }
            },
        )
        checkme.context = serverctx

        clientsite = resource.Site()
        clientsite.add_resource(["whoami"], WhoAmI())
        clientctx = await aiocoap.Context.create_client_context()
        clientctx.serversite = clientsite

        response = await clientctx.request(
            aiocoap.Message(code=aiocoap.POST, uri="coap://localhost:5002/checkme")
        ).response_raising
        self.assertRegex(response.payload.decode("utf8"), ":5002")
