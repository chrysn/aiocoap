# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
import aiocoap

from .test_server import WithTestServer, WithClient, no_warnings


class TestClientWithSetHost(WithTestServer, WithClient):
    @no_warnings
    async def test_uri_path_abbrev_wkc(self):
        request = aiocoap.Message(
            code=aiocoap.GET,
            # We don't set a path, thus are still free to set an abbrev path instead
            uri="coap://" + self.servernetloc,
            uri_path_abbrev=0,
        )
        response = await self.client.request(request).response_raising
        # /.well-known/core is the only resource in the default server in that
        # format
        self.assertEqual(response.opt.content_format, 40)

    @no_warnings
    async def test_uri_path_abbrev_in_request_uri(self):
        request = aiocoap.Message(
            code=aiocoap.GET, uri="coap://" + self.servernetloc, uri_path_abbrev=0
        )
        self.assertEqual(
            request.get_request_uri(),
            "coap://" + self.servernetloc + "/.well-known/core",
        )

    @no_warnings
    async def test_uri_path_abbrev_conflict(self):
        uri = "coap://" + self.servernetloc + "/path"
        request = aiocoap.Message(
            code=aiocoap.GET,
            uri=uri,
            uri_path_abbrev=0,
        )
        # Hack to get past the credentials dispatch -- otherwise we can't
        # even form the request URI to decide credentials.
        request.get_request_uri = lambda *, _uri=uri: _uri
        response = await self.client.request(request).response
        self.assertEqual(response.code, aiocoap.BAD_OPTION)

    @no_warnings
    async def test_uri_path_abbrev_unknown(self):
        uri = "coap://" + self.servernetloc
        request = aiocoap.Message(
            code=aiocoap.GET,
            uri=uri,
            uri_path_abbrev=1234,
        )
        # Hack to get past the credentials dispatch -- otherwise we can't
        # even form the request URI to decide credentials.
        request.get_request_uri = lambda *, _uri=uri: _uri
        response = await self.client.request(request).response
        self.assertEqual(response.code, aiocoap.BAD_OPTION)
