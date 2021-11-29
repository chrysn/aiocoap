# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This tests advanced cases of blockwise transfer; simple sequential transfers
are covered in test_server.TestServer.test_replacing_resource."""

import asyncio

import unittest
import aiocoap
import aiocoap.defaults

from .test_server import WithTestServer, WithClient, no_warnings, asynctest, BigResource, BasicTestingSite

class BigChunkyResource(BigResource):
    async def render_get(self, request):
        request.remote.maximum_block_size_exp = 3
        return await super().render_get(request)

class ChunkyTestingSite(BasicTestingSite):
    def __init__(self):
        super().__init__()

        self.add_resource(["big", "chunky"], BigChunkyResource())

class WithChunkyTestServer(WithTestServer):
    TestingSite = ChunkyTestingSite

class TestBlockwise(WithChunkyTestServer, WithClient):
    # tracked as https://github.com/chrysn/aiocoap/issues/58; behavior can be successful more or less by chance
    @unittest.skip
    @no_warnings
    @asynctest
    async def test_sequential(self):
        """Test whether the client serializes simultaneous block requests"""

        pattern1 = b"01234 first pattern" + b"01" * 1024
        pattern2 = b"01234 second pattern" + b"02" * 1024

        request1 = aiocoap.Message(
                uri='coap://' + self.servernetloc + '/replacing/one',
                code=aiocoap.POST,
                payload=pattern1,
                )
        request2 = aiocoap.Message(
                uri='coap://' + self.servernetloc + '/replacing/one',
                code=aiocoap.POST,
                payload=pattern2,
                )

        responses = []
        for response in asyncio.as_completed([self.client.request(r).response for r in [request1, request2]]):
            response = await response
            self.assertTrue(response.code.is_successful(), "Simultaneous blockwise requests caused error.")
            responses.append(response.payload)

        self.assertSetEqual(set(responses), set(x.replace(b'0', b'O') for x in (pattern1, pattern2)))

    @no_warnings
    @asynctest
    async def test_client_hints(self):
        """Test whether a handle_blockwise=True request takes a block2 option
        set in it as a hint to start requesting with a low size right away

        That way of hinting at size requests is not documented, but understood
        and occasionally used; the test primarily serves to identify problems
        the server has with initially low block sizes."""

        resp = await self.client.request(
                aiocoap.Message(
                    uri='coap://' + self.servernetloc + '/big',
                    block2=(0, 0, 3),
                    code=aiocoap.GET,
                )).response

        self.assertEqual(resp.code, aiocoap.CONTENT, "Request was unsuccessful")
        self.assertEqual(self._count_received_messages(), (len(resp.payload) + 127) // 128, "Response not chunked into 128 bytes")

    @no_warnings
    @asynctest
    async def test_server_hints(self):
        """Test whether the needs_blockwise server mechanism considers size
        exponent limits of the remote.

        Mutating the remote as it is done in the BigChunkyResource is not
        documented, but helps verify that the information in
        maximum_block_size_exp is generally used."""

        resp = await self.client.request(
                aiocoap.Message(
                    uri='coap://' + self.servernetloc + '/big/chunky',
                    code=aiocoap.GET,
                )).response

        self.assertEqual(resp.code, aiocoap.CONTENT, "Request was unsuccessful")
        self.assertEqual(self._count_received_messages(), (len(resp.payload) + 127) // 128, "Response not chunked into 128 bytes")

    _received_logmsg = "Incoming message <aiocoap.Message at"
    def _count_received_messages(self):
        # only client-side received empty-acks are counted
        return sum(self._received_logmsg in x.msg
                for x in self.handler
                if x.name != 'coap-server')
