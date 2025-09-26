# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
import aiocoap
import unittest

from .test_server import WithTestServer, WithClient, no_warnings


class TestClientWithSetHost(WithTestServer, WithClient):
    @no_warnings
    async def test_uri_path_abbrev_wkc(self):
        request = aiocoap.Message(
            code=aiocoap.GET,
            # We don't set a path, thus are still free to set an abbrev path isntead
            uri="coap://" + self.servernetloc,
            uri_path_abbrev=0,
        )
        response = await self.client.request(request).response_raising
        # /.well-known/core is the only resource in the default server in that
        # format
        self.assertEqual(response.opt.content_format, 40)

    @unittest.expectedFailure
    # So far, this is only supported on the server, not on the client
    async def test_uri_path_abbrev_in_request_uri(self):
        request = aiocoap.Message(
            code=aiocoap.GET, uri="coap://" + self.servernetloc, uri_path_abbrev=0
        )
        self.assertEqual(
            request.get_request_uri(),
            "coap://" + self.servernetloc + "/.well-known/core",
        )
