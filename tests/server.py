# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# txThings is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import aiocoap
import aiocoap.resource
import unittest

import pprint
import weakref
import gc

# time granted to asyncio to receive datagrams sent via loopback, and to close
# connections. if tearDown checks fail erratically, tune this up -- but it
# causes per-fixture delays.
CLEANUPTIME = 0.01

class MultiRepresentationResource(aiocoap.resource.CoAPResource):
    @asyncio.coroutine
    def render_GET(self, request):
        ct = request.opt.accept or aiocoap.numbers.media_types_rev['text/plain']

        if ct == aiocoap.numbers.media_types_rev['application/json']:
            response = b'{}'
        elif ct == aiocoap.numbers.media_types_rev['application/link-format']:
            response = b'<>'
        elif ct == aiocoap.numbers.media_types_rev['text/plain']:
            response = b''
        else:
            return aiocoap.Message(code=aiocoap.NOT_ACCEPTABLE)

        return aiocoap.Message(code=aiocoap.CONTENT, payload=response)

class SlowResource(aiocoap.resource.CoAPResource):
    @asyncio.coroutine
    def render_GET(self, request):
        yield from asyncio.sleep(0.2)
        return aiocoap.Message(code=aiocoap.CONTENT)

class BigResource(aiocoap.resource.CoAPResource):
    @asyncio.coroutine
    def render_GET(self, request):
        # 10kb
        payload = b"0123456789----------" * 512
        return aiocoap.Message(code=aiocoap.CONTENT, payload=payload)

class ReplacingResource(aiocoap.resource.CoAPResource):
    @asyncio.coroutine
    def render_GET(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=self.value)

    @asyncio.coroutine
    def render_PUT(self, request):
        self.value = request.payload.replace(b'0', b'O')
        return aiocoap.Message(code=aiocoap.CHANGED)

    @asyncio.coroutine
    def render_POST(self, request):
        response = request.payload.replace(b'0', b'O')
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response)

class TestingSite(aiocoap.resource.Site):
    def __init__(self):
        root = aiocoap.resource.CoAPResource()
        root.put_child('empty', MultiRepresentationResource())
        root.put_child('slow', SlowResource())
        root.put_child('big', BigResource())
        root.put_child('replacing', ReplacingResource())

        super(TestingSite, self).__init__(root)

class TypeCounter(object):
    """This is an ExchangeMonitor factory and counts the outcomes of all
    exchanges"""
    def __init__(self):
        self.empty_ack_count = 0

    def __call__(self, message):
        return self.BoundCounter(self)

    class BoundCounter(aiocoap.protocol.ExchangeMonitor):
        def __init__(self, counter):
            self.counter = counter

        def response(self, message):
            if message.mtype == aiocoap.ACK and message.code == aiocoap.EMPTY:
                self.counter.empty_ack_count += 1

# fixtures

class WithAsyncLoop(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()

class WithTestServer(WithAsyncLoop):
    def setUp(self):
        super(WithTestServer, self).setUp()

        ts = TestingSite()
        self.server = self.loop.run_until_complete(aiocoap.Endpoint.create_server_endpoint(ts))

    def tearDown(self):
        # let the server receive the acks we just sent
        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))
        self.server.transport.close()
        weakproto = weakref.ref(self.server)
        del self.server
        # let everything that gets async-triggered by close() happen
        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))
        gc.collect()
        proto = weakproto()
        if proto is not None:
            # if-clause so string formatting can assume proto is not None
            self.fail("Protocol was not garbage collected.\n\nReferrers: %s\n\nProperties: %s"%(pprint.pformat(referrers), pprint.pformat(vars(proto))))

class WithClient(WithAsyncLoop):
    def setUp(self):
        super(WithClient, self).setUp()

        self.client = self.loop.run_until_complete(aiocoap.Endpoint.create_client_endpoint())

    def tearDown(self):
        self.client.transport.close()

# test cases

class TestServer(WithTestServer, WithClient):
    def build_request(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.remote = ('127.0.0.1', aiocoap.COAP_PORT)
        return request

    def fetch_response(self, request, exchange_monitor_factory=lambda x:None):
        #return self.loop.run_until_complete(self.client.request(request))

        requester = aiocoap.protocol.Requester(self.client, request, exchange_monitor_factory)
        return self.loop.run_until_complete(requester.response)

    def test_empty_accept(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Simple request did not succede")
        self.assertEqual(response.payload, b'', "Simple request gave unexpected result")

    def test_unacceptable_accept(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']
        request.opt.accept = 9999
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.NOT_ACCEPTABLE, "Inacceptable request was not not accepted")

    def test_js_accept(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']
        request.opt.accept = aiocoap.numbers.media_types_rev['application/json']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "JSON request did not succede")
        self.assertEqual(response.payload, b'{}', "JSON request gave unexpected result")

    def test_nonexisting_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['nonexisting']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.NOT_FOUND, "Nonexisting resource was not not found")

    def test_spurious_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['..', 'empty']
        response = self.fetch_response(request)
        # different behavior would be ok-ish, as the .. in the request is forbidden, but returning 4.04 is sane here
        self.assertEqual(response.code, aiocoap.NOT_FOUND, "'..' component in path did not get ignored the way it was expected")

    def test_fast_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['empty']

        counter = TypeCounter()

        response = self.fetch_response(request, counter)

        self.assertEqual(response.code, aiocoap.CONTENT, "Fast request did not succede")
        self.assertEqual(counter.empty_ack_count, 0, "Fast resource had an empty ack")

    def test_slow_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['slow']

        counter = TypeCounter()

        response = self.fetch_response(request, counter)

        self.assertEqual(response.code, aiocoap.CONTENT, "Slow request did not succede")
        self.assertEqual(counter.empty_ack_count, 1, "Slow resource was not handled in two exchanges")

    def test_big_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['big']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Big resource request did not succede")
        self.assertEqual(len(response.payload), 10240, "Big resource is not as big as expected")

    def test_replacing_resource(self):
        testpattern = b"01" * 1024

        request = self.build_request()
        request.code = aiocoap.PUT
        request.payload = testpattern
        request.opt.uri_path = ['replacing']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CHANGED, "PUT did not result in CHANGED")
        self.assertEqual(response.payload, b"", "PUT has unexpected payload")

        request = self.build_request()
        request.code = aiocoap.GET
        request.opt.uri_path = ['replacing']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Replacing resource could not be GOT (GET'd?) successfully")
        self.assertEqual(response.payload, testpattern.replace(b"0", b"O"), "Replacing resource did not replace as expected between PUT and GET")

        request = self.build_request()
        request.code = aiocoap.POST
        request.payload = testpattern
        request.opt.uri_path = ['replacing']
        response = self.fetch_response(request)
        self.assertEqual(response.code, aiocoap.CONTENT, "Replacing resource could not be POSTed to successfully")
        self.assertEqual(response.payload, testpattern.replace(b"0", b"O"), "Replacing resource did not replace as expected when POSTed")

#import logging
#logging.basicConfig()
#logging.getLogger("coap").setLevel(logging.DEBUG)
#logging.getLogger("coap-server").setLevel(logging.DEBUG)

# for testing the server standalone
if __name__ == "__main__":
    print("Running test server")
    s = WithTestServer()
    s.setUp()
    try:
        s.loop.run_forever()
    except KeyboardInterrupt:
        print("Shutting down test server")
        s.tearDown()
