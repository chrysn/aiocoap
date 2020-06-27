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
            result = await asyncio.as_completed([resp], timeout=0.1).__next__()
        except aiocoap.error.NetworkError as e:
            # This is a bit stricter than what the API indicates, but hey, we
            # can still relax the tests.
            self.assertTrue(isinstance(e.__cause__, OSError))
            # ECONNREFUSED: linux; ECONNRESET: win32
            self.assertTrue(e.__cause__.errno in (errno.ECONNREFUSED, errno.ECONNRESET))
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

    @no_warnings
    @asynctest
    async def test_freeoncancel(self):
        # As there's no programmatic feedback about what actually gets sent,
        # looking at the logs is the easiest option, even though it will
        # require occasional adjustment when logged messages change.
        #
        # FIXME Currently, this *only* checks for whether later responses are
        # rejected, it does *not* check for whether the response runner is
        # freed as well (primarily because that'd need _del_to_be_sure to be
        # useable in an async context).

        # With immediate cancellation, nothing is sent. Note that we don't
        # ensure this per documentation, but still it's good to see when this
        # changes.
        loglength = len(self.handler.list)
        request = aiocoap.Message(code=aiocoap.GET, uri="coap://" + self.servernetloc + "/empty")
        self.resp = self.client.request(request).response
        self.resp.cancel()
        self.assertEqual(loglength, len(self.handler.list), "Something was logged during request creation and immediate cancellation: %r" % (self.handler.list[loglength:],))

        # With a NON, the response should take long. (Not trying to race the
        # "I'm taking too long"-ACK by making the sleep short enough).
        # Note that the resource implementation deliberately sends responses as CON,
        # as to allow us to peek into the internals of aiocoap by
        # looking at wehter it returns a RST or an ACK.
        request = aiocoap.Message(code=aiocoap.GET, uri="coap://" + self.servernetloc + "/slow", mtype=aiocoap.NON)
        self.resp = self.client.request(request).response
        # Wait for the request to actually be sent
        while not any('Sending request' in l.getMessage() for l in self.handler.list):
            await asyncio.sleep(0.001)
        # Now the request was sent, let's look at what happens during and after the cancellation
        loglength = len(self.handler.list)
        self.resp.cancel()
        await asyncio.sleep(0.4) # server takes 0.2 to respond
        logmsgs = self.handler.list[loglength:]
        unmatched_msgs = [l for l in logmsgs if "could not be matched to any request" in l.getMessage()]
        self.assertEqual(len(unmatched_msgs), 1, "The incoming response was not treated as unmatched")
