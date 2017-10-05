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

from .test_server import WithTestServer, WithClient, no_warnings

if 'simple6' in aiocoap.defaults.get_default_clienttransports():
    # simple6 has the (comparatively) odd property that whenever it resolves an
    # address it creates a new client port. Two blockwise requests thus can
    # proceed without error even when they are simultaneous.
    expectedFailure_unless_simple6 = lambda x:x
else:
    expectedFailure_unless_simple6 = unittest.expectedFailure

class TestBlockwise(WithTestServer, WithClient):
    @expectedFailure_unless_simple6
    @no_warnings
    def test_sequential(self):
        """Test whether the client serializes simultaneous block requests"""
        self.loop.run_until_complete(self._test_sequential())

    @asyncio.coroutine
    def _test_sequential(self):
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
            response = yield from response
            self.assertTrue(response.code.is_successful(), "Simultaneous blockwise requests caused error.")
            responses.append(response.payload)

        self.assertSetEqual(set(responses), set(x.replace(b'0', b'O') for x in (pattern1, pattern2)))
