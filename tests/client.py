# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import aiocoap
import unittest

from .server import WithTestServer, WithClient, no_warnings

class TestClient(WithTestServer, WithClient):
    @no_warnings
    def test_uri_parser(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri("coap://127.0.0.1/empty")
        response = self.loop.run_until_complete(self.client.request(request))
        self.assertEqual(response.code, aiocoap.CONTENT, "Request URL building failed")

        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri("coap://localhost/empty")
        self.assertEqual(request.get_request_uri(), "coap://localhost/empty")
        response = self.loop.run_until_complete(self.client.request(request))
        self.assertEqual(response.code, aiocoap.CONTENT, "Resolving localhost failed")
        self.assertEqual(response.get_request_uri(), "coap://localhost/empty", "Host name did not get round-tripped")

        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri("coap://127.0.0.1:9999/empty")
        t = asyncio.Task(self.client.request(request))
        try:
            # give the request some time to finish getaddrinfo
            self.loop.run_until_complete(asyncio.as_completed([t], timeout=0.01).__next__())
        except asyncio.TimeoutError:
            pass
        self.assertEqual(request.remote[1], 9999, "Remote port was not parsed")
        t.cancel()
