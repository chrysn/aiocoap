# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import aiocoap
import aiocoap.resource
import unittest

import logging

import pprint
import weakref
import gc

# time granted to asyncio to receive datagrams sent via loopback, and to close
# connections. if tearDown checks fail erratically, tune this up -- but it
# causes per-fixture delays.
CLEANUPTIME = 0.01

class MultiRepresentationResource(aiocoap.resource.Resource):
    @asyncio.coroutine
    def render_get(self, request):
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

class SlowResource(aiocoap.resource.Resource):
    @asyncio.coroutine
    def render_get(self, request):
        yield from asyncio.sleep(0.2)
        return aiocoap.Message(code=aiocoap.CONTENT)

class BigResource(aiocoap.resource.Resource):
    @asyncio.coroutine
    def render_get(self, request):
        # 10kb
        payload = b"0123456789----------" * 512
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=payload)

        aiocoap.resource.hashing_etag(request, response)
        return response

class SlowBigResource(aiocoap.resource.Resource):
    @asyncio.coroutine
    def render_get(self, request):
        yield from asyncio.sleep(0.2)
        # 1.6kb
        payload = b"0123456789----------" * 80
        return aiocoap.Message(code=aiocoap.CONTENT, payload=payload)

class ReplacingResource(aiocoap.resource.Resource):
    @asyncio.coroutine
    def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=self.value)

    @asyncio.coroutine
    def render_put(self, request):
        self.value = request.payload.replace(b'0', b'O')
        return aiocoap.Message(code=aiocoap.CHANGED)

    @asyncio.coroutine
    def render_post(self, request):
        response = request.payload.replace(b'0', b'O')
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response)

class TestingSite(aiocoap.resource.Site):
    def __init__(self):
        super(TestingSite, self).__init__()

        self.add_resource(('empty',), MultiRepresentationResource())
        self.add_resource(('slow',), SlowResource())
        self.add_resource(('big',), BigResource())
        self.add_resource(('slowbig',), SlowBigResource())
        self.add_resource(('replacing',), ReplacingResource())

# helpers

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

def no_warnings(function):
    def wrapped(self, *args, function=function):
        # assertLogs does not work as assertDoesntLog anyway without major
        # tricking, and it interacts badly with WithLogMonitoring as they both
        # try to change the root logger's level.

        startcount = len(self.handler)
        result = function(self, *args)
        messages = [m.msg for m in self.handler[startcount:] if m.levelno >= logging.WARNING]
        self.assertEqual(messages, [], "Function %s had warnings: %s"%(function.__name__, messages))
        return result
    wrapped.__name__ = function.__name__
    wrapped.__doc__ = function.__doc__
    return wrapped

# fixtures

class WithLogMonitoring(unittest.TestCase):
    def setUp(self):
        self.handler = self.ListHandler()

        logging.root.setLevel(0)
        logging.root.addHandler(self.handler)

        super(WithLogMonitoring, self).setUp()

    def tearDown(self):
        super(WithLogMonitoring, self).tearDown()

        logging.root.removeHandler(self.handler)
#
#        formatter = logging.Formatter(fmt='%(levelname)s:%(name)s:%(message)s')
#        print("fyi:\n", "\n".join(formatter.format(x) for x in self.handler if x.name != 'asyncio'))

    class ListHandler(logging.Handler, list):
        def emit(self, record):
            self.append(record)

class WithAsyncLoop(unittest.TestCase):
    def setUp(self):
        super(WithAsyncLoop, self).setUp()

        self.loop = asyncio.get_event_loop()

class Destructing(WithLogMonitoring):
    def _del_to_be_sure(self, attribute):
        weaksurvivor = weakref.ref(getattr(self, attribute))
        delattr(self, attribute)
        # let everything that gets async-triggered by close() happen
        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))
        gc.collect()
        survivor = weaksurvivor()
        if survivor is not None:
            snapshot = lambda: "Referrers: %s\n\nProperties: %s"%(pprint.pformat(gc.get_referrers(survivor)), pprint.pformat(vars(survivor)))
            snapshot1 = snapshot()
            if False: # enable this if you think that a longer timeout would help
                # this helped finding that timer cancellations don't free the
                # callback, but in general, expect to modify this code if you
                # have to read it; this will need adjustment to your current
                # debugging situation
                logging.root.info("Starting extended grace period")
                for i in range(10):
                    self.loop.run_until_complete(asyncio.sleep(1))
                    del survivor
                    gc.collect()
                    survivor = weaksurvivor()
                    logging.root.info("Now %ds into grace period, survivor is %r"%((i+1)/1, survivor))
                    if survivor is None:
                        break
                snapshot2 = snapshot() if survivor else "no survivor"
                snapshotsmessage = "Before extended grace period:\n" + snapshot1 + "\n\nAfter extended grace period:\n" + snapshot2
            else:
                snapshotsmessage = snapshot1
            formatter = logging.Formatter(fmt='%(levelname)s:%(name)s:%(message)s')
            errormessage = "Protocol %s was not garbage collected.\n\n"%attribute + snapshotsmessage + "\n\nLog of the unit test:\n" + "\n".join(formatter.format(x) for x in self.handler)
            self.fail(errormessage)

class WithTestServer(WithAsyncLoop, Destructing):
    def create_testing_site(self):
        return TestingSite()

    def setUp(self):
        super(WithTestServer, self).setUp()

        self.server = self.loop.run_until_complete(aiocoap.Context.create_server_context(self.create_testing_site()))

    def tearDown(self):
        # let the server receive the acks we just sent
        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))
        self.loop.run_until_complete(self.server.shutdown())
        self._del_to_be_sure("server")

        super(WithTestServer, self).tearDown()

    serveraddress = "::1"
    servernetloc = "[%s]"%serveraddress
    servernamealias = "ip6-loopback"

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

    @no_warnings
    def fetch_response(self, request, exchange_monitor_factory=lambda x:None):
        return self.loop.run_until_complete(self.client.request(request, exchange_monitor_factory=exchange_monitor_factory).response)

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

        counter = TypeCounter()

        response = self.fetch_response(request, counter)

        self.assertEqual(response.code, aiocoap.CONTENT, "Fast request did not succede")
        self.assertEqual(counter.empty_ack_count, 0, "Fast resource had an empty ack")

    @no_warnings
    def test_slow_resource(self):
        request = self.build_request()
        request.opt.uri_path = ['slow']

        counter = TypeCounter()

        response = self.fetch_response(request, counter)

        self.assertEqual(response.code, aiocoap.CONTENT, "Slow request did not succede")
        self.assertEqual(counter.empty_ack_count, 1, "Slow resource was not handled in two exchanges")

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
        counter = TypeCounter()
        response = self.fetch_response(request, counter)
        self.assertEqual(response.code, aiocoap.CONTENT, "SlowBig resource request did not succede")
        self.assertEqual(len(response.payload), 1600, "SlowBig resource is not as big as expected")
        self.assertEqual(counter.empty_ack_count, 1, "SlowBig resource was not handled in two exchanges")

    @no_warnings
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

#logging.basicConfig()
#logging.getLogger("coap").setLevel(logging.DEBUG)
#logging.getLogger("coap-server").setLevel(logging.INFO)

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
