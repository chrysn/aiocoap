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
import errno

from .test_server import WithTestServer, WithClient, no_warnings, asynctest

class TestClientWithSetHost(WithTestServer, WithClient):
    set_uri_host = True

    @no_warnings
    @asynctest
    async def test_uri_parser(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request_uri = "coap://" + self.servernetloc + "/empty?query=a&query=b"
        request.set_request_uri(request_uri, set_uri_host=self.set_uri_host)
        self.assertEqual(request.get_request_uri(), request_uri, "Request URL does not round-trip in request")
        response = await self.client.request(request).response
        self.assertEqual(response.get_request_uri(), request_uri, "Request URL does not round-trip in response")
        self.assertEqual(response.code, aiocoap.CONTENT, "Request URL building failed")

        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri("coap://" + self.servernamealias + "/empty", set_uri_host=self.set_uri_host)
        self.assertEqual(request.get_request_uri(), "coap://" + self.servernamealias + "/empty")
        response = await self.client.request(request).response
        self.assertEqual(response.code, aiocoap.CONTENT, "Resolving WithTestServer.servernamealias failed")
        if self.set_uri_host:
            self.assertEqual(response.get_request_uri(), "coap://" + self.servernamealias + "/empty", "Host name did not get round-tripped")
        else:
            # The simple6 transport misreports remotes to which a socket was
            # opened with a name.
            if 'simple6' not in list(aiocoap.defaults.get_default_clienttransports(loop=self.loop)):
                self.assertEqual(response.get_request_uri(), "coap://" + self.servernetloc + "/empty", "Response's request URI is not numeric in hostname-less query")

    @no_warnings
    @asynctest
    async def test_uri_parser2(self):
        """A difficult test because it is prone to keeping the transport
        around, bothering later tests"""

        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri("coap://" + self.servernetloc + ":9999/empty", set_uri_host=self.set_uri_host)
        resp = self.client.request(request).response
        try:
            # give the request some time to finish getaddrinfo
            result = await asyncio.as_completed([resp], timeout=0.01).__next__()
        except OSError as e:
            self.assertEqual(e.errno, errno.ECONNREFUSED, "")
        except asyncio.TimeoutError:
            self.fail("Request to non-opened port did not come back with 'Connection Refused' immediately")
        else:
            self.fail("Request to non-opened port did not come back with 'Connection Refused', but another result: %s"%(result,))
        self.assertTrue(request.remote.hostinfo.endswith(':9999'), "Remote port was not parsed")
        resp.cancel()

class TestClientWithHostlessMessages(TestClientWithSetHost):
    set_uri_host = False

class TestClientOther(WithTestServer, WithClient):
    @no_warnings
    # can't do @asynctest because of assertRaises
    def test_raising(self):
        """This test obtains results via the response_raising property of a
        Request."""
        yieldfrom = self.loop.run_until_complete

        request = aiocoap.Message(code=aiocoap.GET, uri="coap://" + self.servernetloc + "/empty")
        response = yieldfrom(self.client.request(request).response_raising)
        self.assertEqual(response.code, aiocoap.CONTENT, "Response access via response_raising failed")

        request = aiocoap.Message(code=aiocoap.GET, uri="coap://" + self.servernetloc + "/nonexistent")
        ## @FIXME i'd like to assertRaises(NotFound), see docstring of
        # :class:`ResponseWrappingError`
        self.assertRaises(aiocoap.error.ResponseWrappingError, yieldfrom,
                self.client.request(request).response_raising)

    @no_warnings
    @asynctest
    async def test_nonraising(self):
        """This test obtains results via the response_nonraising property of a
        Request."""
        request = aiocoap.Message(code=aiocoap.GET, uri="coap://" + self.servernetloc + "/empty")
        response = await self.client.request(request).response_nonraising
        self.assertEqual(response.code, aiocoap.CONTENT, "Response access via response_nonraising failed")

        request = aiocoap.Message(code=aiocoap.GET, uri="coap://cant.resolve.this.example./empty")
        response = await self.client.request(request).response_nonraising
        self.assertEqual(response.code, aiocoap.INTERNAL_SERVER_ERROR)
