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

import weakref
import gc

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

class TestingSite(aiocoap.resource.Site):
    def __init__(self):
        root = aiocoap.resource.CoAPResource()
        root.put_child('empty', MultiRepresentationResource())
        root.put_child('slow', SlowResource())

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
        self.server.transport.close()
        weakproto = weakref.ref(self.server)
        del self.server
        self.loop.run_until_complete(asyncio.sleep(0.1))
        self.assertEqual(weakproto(), None, "Protocol did not get garbage collected (holders: %s)"%gc.get_referrers(weakproto()))

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

    def test_nonexisting_resource(self):
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
