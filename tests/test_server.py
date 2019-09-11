# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import re
import aiocoap
import aiocoap.resource
import unittest
import logging

from . import common
from .fixtures import (WithLogMonitoring, no_warnings, precise_warnings,
    WithAsyncLoop, Destructing, CLEANUPTIME, asynctest)

class MultiRepresentationResource(aiocoap.resource.Resource):
    def __init__(self, representations):
        self._representations = representations
        super().__init__()

    async def render_get(self, request):
        m = aiocoap.numbers.media_types.get(request.opt.accept or 0, None)

        if m in self._representations:
            response = self._representations[m]
        else:
            return aiocoap.Message(code=aiocoap.NOT_ACCEPTABLE)

        return aiocoap.Message(payload=response, content_format=request.opt.accept or 0)

class SlowResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        await asyncio.sleep(0.2)
        return aiocoap.Message()

class BigResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        # 10kb
        payload = b"0123456789----------" * 512
        response = aiocoap.Message(payload=payload)

        aiocoap.resource.hashing_etag(request, response)
        return response

class SlowBigResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        await asyncio.sleep(0.2)
        # 1.6kb
        payload = b"0123456789----------" * 80
        return aiocoap.Message(payload=payload)

class ReplacingResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(payload=self.value)

    async def render_put(self, request):
        self.value = request.payload.replace(b'0', b'O')
        return aiocoap.Message()

    async def render_post(self, request):
        response = request.payload.replace(b'0', b'O')
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response)

class RootResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=b"Welcome to the test server")

class TestingSite(aiocoap.resource.Site):
    def __init__(self):
        super(TestingSite, self).__init__()

        # Not part of the test suite, but handy when running standalone
        self.add_resource(['.well-known', 'core'], aiocoap.resource.WKCResource(self.get_resources_as_linkheader))

        self.add_resource(['empty'], MultiRepresentationResource({
            'application/json': b'{}',
            'application/link-format': b'<>',
            'text/plain;charset=utf-8': b'',
            }))
        self.add_resource(['answer'], MultiRepresentationResource({
            'application/json': b'{"answer": 42}',
            'application/cbor': b'\xa1\x66\x61\x6e\x73\x77\x65\x72\x18\x2a',
            'application/link-format': b'<data:text/plain;42>;rel="answer";anchor="https://en.wikipedia.org/wiki/Phrases_from_The_Hitchhiker%27s_Guide_to_the_Galaxy#Answer_to_the_Ultimate_Question_of_Life,_the_Universe,_and_Everything_(42)"',
            'text/plain;charset=utf-8': b'The answer to life, the universe, and everything is 42.',
            }))
        self.add_resource(['slow'], SlowResource())
        self.add_resource(['big'], BigResource())
        self.add_resource(['slowbig'], SlowBigResource())
        self.add_resource(['replacing'], self.Subsite())
        self.add_resource([], RootResource())

    class Subsite(aiocoap.resource.Site):
        def __init__(self):
            super().__init__()
            self.add_resource(['one'], ReplacingResource())


class WithTestServer(WithAsyncLoop, Destructing):
    # to allow overriding the factory class
    TestingSite = TestingSite

    def create_testing_site(self):
        return self.TestingSite()

    def setUp(self):
        super(WithTestServer, self).setUp()

        self.server = self.loop.run_until_complete(aiocoap.Context.create_server_context(self.create_testing_site(), bind=(self.serveraddress, None)))

    def tearDown(self):
        # let the server receive the acks we just sent
        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))
        self.loop.run_until_complete(self.server.shutdown())
        self._del_to_be_sure("server")

        super(WithTestServer, self).tearDown()

    serveraddress = "::1"
    servernetloc = "[%s]"%serveraddress
    servernamealias = common.loopbackname_v6 or common.loopbackname_v46

class WithClient(WithAsyncLoop, Destructing):
    def setUp(self):
        super(WithClient, self).setUp()

        self.client = self.loop.run_until_complete(aiocoap.Context.create_client_context())

    def tearDown(self):
        self.loop.run_until_complete(self.client.shutdown())

        self._del_to_be_sure("client")

        super(WithClient, self).tearDown()

# test cases

class TestServer(WithTestServer, WithClient):
    @no_warnings
    def build_request(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.servernetloc
        return request

    @asynctest
    async def fetch_response(self, request):
        return await self.client.request(request).response

    @no_warnings
    def test_empty_accept(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Simple request did not succede")
        self.assertEqual(response.payload, b'', "Simple request gave unexpected result")

    @no_warnings
    def test_unacceptable_accept(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']
        request.opt.accept = 9999
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.NOT_ACCEPTABLE, "Inacceptable request was not not accepted")

    @no_warnings
    def test_js_accept(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']
        request.opt.accept = aiocoap.numbers.media_types_rev['application/json']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "JSON request did not succede")
        self.assertEqual(response.payload, b'{}', "JSON request gave unexpected result")

    @no_warnings
    def test_nonexisting_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['nonexisting']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.NOT_FOUND, "Nonexisting resource was not not found")

    @no_warnings
    def test_spurious_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['..', 'empty']
        response = self.fetch_response(request)
        # different behavior would be ok-ish, as the .. in the request is forbidden, but returning 4.04 is sane here
        self.assertEqual(response.code, aiocoap.NOT_FOUND, "'..' component in path did not get ignored the way it was expected")

    @no_warnings
    def test_fast_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']

        response = self.fetch_response(request)

        self.assertEqual(response.code, aiocoap.CONTENT, "Fast request did not succede")
        self.assertEqual(self._count_empty_acks(), 0, "Fast resource had an empty ack")

    @no_warnings
    def test_slow_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['slow']

        response = self.fetch_response(request)

        self.assertEqual(response.code, aiocoap.CONTENT, "Slow request did not succede")
        if response.requested_scheme in (None, 'coap'):
            self.assertEqual(self._count_empty_acks(), 1, "Slow resource was not handled in two exchanges")

    @no_warnings
    def test_big_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['big']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Big resource request did not succede")
        self.assertEqual(len(response.payload), 10240, "Big resource is not as big as expected")

        self.assertTrue(response.opt.etag != None, "Big resource does not provide an ETag")

        request = self.build_request()
        request.opt.uri_path = ['big']
        request.opt.etags = [response.opt.etag]
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.VALID, "Big resource does not support ETag validation")
        self.assertTrue(response.opt.etag != None, "Big resource does not send ETag for validation")

    @no_warnings
    def test_slowbig_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['slowbig']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "SlowBig resource request did not succede")
        self.assertEqual(len(response.payload), 1600, "SlowBig resource is not as big as expected")
        if response.requested_scheme in (None, 'coap'):
            self.assertEqual(self._count_empty_acks(), 1, "SlowBig resource was not handled in two exchanges")

    @no_warnings
    def test_replacing_resource(self):
        testpattern = b"01" * 1024

        request = self.build_request()
        request.code = aiocoap.PUT
        request.payload = testpattern
        request.opt.uri_path = ['replacing', 'one']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CHANGED, "PUT did not result in CHANGED")
        self.assertEqual(response.payload, b"", "PUT has unexpected payload")

        request = self.build_request()
        request.code = aiocoap.GET
        request.opt.uri_path = ['replacing', 'one']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Replacing resource could not be GOT (GET'd?) successfully")
        self.assertEqual(response.payload, testpattern.replace(b"0", b"O"), "Replacing resource did not replace as expected between PUT and GET")

        request = self.build_request()
        request.code = aiocoap.POST
        request.payload = testpattern
        request.opt.uri_path = ['replacing', 'one']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Replacing resource could not be POSTed to successfully")
        self.assertEqual(response.payload, testpattern.replace(b"0", b"O"), "Replacing resource did not replace as expected when POSTed")

    @no_warnings
    def test_root_resource(self):
        request = self.build_request()
        request.opt.uri_path = []
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Root resource was not found")


    _empty_ack_logmsg = re.compile("^Incoming message <aiocoap.Message at"
                                   " 0x[0-9a-f]+: Type.ACK EMPTY ([^)]+)")
    def _count_empty_acks(self):
        # only client-side received empty-acks are counted; they typically
        # generate an empty ack back when the separate response is ack'd.
        return sum(self._empty_ack_logmsg.match(x.msg) is not None
                for x in
                self.handler
                if x.name != 'coap-server')

@unittest.skipIf(common.tcp_disabled, "TCP disabled in environment")
class TestServerTCP(TestServer):
    # no modification in server setup necessary, as by default, all transports
    # are enabled on servers.

    def build_request(self):
        request = super().build_request()
        request.requested_scheme = 'coap+tcp'
        return request

def run_fixture_as_standalone_server(fixture):
    import sys
    if '-v' in sys.argv:
        logging.basicConfig()
        logging.getLogger("coap").setLevel(logging.DEBUG)
        logging.getLogger("coap-server").setLevel(logging.DEBUG)

    print("Running test server")
    s = fixture()
    s.setUp()
    try:
        s.loop.run_forever()
    except KeyboardInterrupt:
        print("Shutting down test server")
        s.tearDown()

if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_server`
    run_fixture_as_standalone_server(WithTestServer)
