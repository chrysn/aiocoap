# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Tests for resource observation

Note that cancellation of observations is checked in neither way; that's
largely because the implementation has fallen behind on the drafts anyway and
needs to be updated."""

import asyncio
import aiocoap
import gc

from aiocoap.resource import ObservableResource, WKCResource
from .test_server import WithTestServer, WithClient, no_warnings, precise_warnings, ReplacingResource, MultiRepresentationResource, run_fixture_as_standalone_server

class ObservableCounter(ObservableResource):
    def __init__(self):
        super(ObservableCounter, self).__init__()
        self.count = 0

    @asyncio.coroutine
    def render_delete(self, request):
        self.count = 0
        self.updated_state()
        return aiocoap.Message(code=aiocoap.CHANGED)

    @asyncio.coroutine
    def render_post(self, request):
        self.count += 1
        self.updated_state()
        return aiocoap.Message(code=aiocoap.CHANGED)

    @asyncio.coroutine
    def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=str(self.count).encode('ascii'))

    @asyncio.coroutine
    def render_fetch(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT,
                payload=("%s; request had length %s"%(self.count, len(request.payload))).encode('ascii'))

class ObservableReplacingResource(ReplacingResource, ObservableResource):
    @asyncio.coroutine
    def render_put(self, request):
        result = yield from super(ObservableReplacingResource, self).render_put(request)

        self.updated_state()

        return result

class ObserveLateUnbloomer(ObservableResource):
    """A resource that accepts the server observation at first but at rendering
    time decides it can't do it"""
    def __init__(self):
        super().__init__()
        self._cancel_right_away = []

    @asyncio.coroutine
    def add_observation(self, request, serverobservation):
        self._cancel_right_away.append(lambda: serverobservation.deregister("Changed my mind at render time"))
        serverobservation.accept(lambda: None)

    @asyncio.coroutine
    def render_get(self, request):
        while self._cancel_right_away:
            self._cancel_right_away.pop(0)()
        return aiocoap.Message()

class ObservableFailure(ObservableResource):
    @asyncio.coroutine
    def render_get(self, request):
        return aiocoap.Message(code=aiocoap.UNAUTHORIZED)

class ObserveTestingSite(aiocoap.resource.Site):
    prefix = ()

    def __init__(self):
        super(ObserveTestingSite, self).__init__()

        self.add_resource(self.prefix + ('unobservable',), MultiRepresentationResource())
        self.add_resource(self.prefix + ('count',), ObservableCounter())
        self.add_resource(self.prefix + ('echo',), ObservableReplacingResource())
        self.add_resource(self.prefix + ('notreally',), ObserveLateUnbloomer())
        self.add_resource(self.prefix + ('failure',), ObservableFailure())

class NestedSite(aiocoap.resource.Site):
    def __init__(self):
        super().__init__()

        # Not part of the test suite, but handy when running standalone
        self.add_resource(('.well-known', 'core'), WKCResource(self.get_resources_as_linkheader))

        self.subsite = ObserveTestingSite()

        self.add_resource(('deep',), self.subsite)

class UnnestedSite(ObserveTestingSite):
    prefix = ('deep',)

class WithObserveTestServer(WithTestServer):
    def create_testing_site(self):
        self.testingsite = NestedSite()
        # use this when you suspect that things go wrong due to nesting;
        # usually not running this because it has no way to fail without nested
        # failing too
        #self.testingsite = UnnestedSite()
        return self.testingsite

class TestObserve(WithObserveTestServer, WithClient):
    @no_warnings
    def test_normal_get(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.opt.uri_path = ['deep', 'count']
        request.unresolved_remote = self.servernetloc

        response = self.loop.run_until_complete(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Normal request did not succede")
        self.assertEqual(response.payload, b'0', "Normal request gave unexpected result")

    def build_observer(self, path, baserequest=None):
        if baserequest is not None:
            request = baserequest
        else:
            request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.servernetloc
        request.opt.uri_path = path
        request.opt.observe = 0

        requester = self.client.request(request)
        observation_results = []
        requester.observation.register_callback(lambda message: observation_results.append(message.payload))
        requester.observation.register_errback(lambda reason: observation_results.append(reason))

        notinterested = lambda: requester.observation.cancel()

        return requester, observation_results, notinterested

    @no_warnings
    def test_unobservable(self):
        yieldfrom = self.loop.run_until_complete

        requester, observation_results, notinterested = self.build_observer(['deep', 'unobservable'])

        response = self.loop.run_until_complete(requester.response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Unobservable base request did not succede")
        self.assertEqual(response.payload, b'', "Unobservable base request gave unexpected result")

        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(str(observation_results), '[NotObservable()]')

    @asyncio.coroutine
    def _change_counter(self, method=aiocoap.POST):
        request = aiocoap.Message(code=method, uri_path=('deep', 'count'))
        request.unresolved_remote = self.servernetloc
        yield from self.client.request(request).response_raising

    def _test_counter(self, baserequest, formatter):
        """Run a counter test with requests built from baserequest. Expect
        response payloads to be equal to the formatter(n) for n being the
        counter value"""
        yieldfrom = self.loop.run_until_complete

        yieldfrom(self._change_counter(aiocoap.DELETE))

        requester, observation_results, notinterested = self.build_observer(['deep', 'count'], baserequest=baserequest)

        response = self.loop.run_until_complete(requester.response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Observe base request did not succede")
        self.assertEqual(response.payload, formatter(0), "Observe base request gave unexpected result")

        yieldfrom(self._change_counter())
        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(observation_results, [formatter(1)])

        yieldfrom(self._change_counter())
        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(observation_results, [formatter(1), formatter(2)])

        notinterested()

    @no_warnings
    def test_counter(self):
        self._test_counter(None, lambda x: str(x).encode('ascii'))

    @no_warnings
    def test_counter_fetch(self):
        self._test_counter(
                aiocoap.Message(code=aiocoap.FETCH, payload=b'12345'),
                lambda x: ('%s; request had length 5'%x).encode('ascii'))

    # Test hard disabled because not only it expects failure, but that failure
    # also causes protocol GC issues. Tracked in
    # https://github.com/chrysn/aiocoap/issues/95
#     @no_warnings
#     def test_counter_fetch_big(self):
#         self._test_counter(
#                 aiocoap.Message(code=aiocoap.FETCH, payload=b'12345' * 1000),
#                 lambda x: ('%s; request had length 5000'%x).encode('ascii'))

    @no_warnings
    def test_echo(self):
        yieldfrom = self.loop.run_until_complete

        def put(b):
            m = aiocoap.Message(code=aiocoap.PUT, payload=b)
            m.unresolved_remote = self.servernetloc
            m.opt.uri_path = ['deep', 'echo']
            response = yieldfrom(self.client.request(m).response)
            self.assertEqual(response.code, aiocoap.CHANGED)

        put(b'test data 1')

        requester, observation_results, notinterested = self.build_observer(['deep', 'echo'])
        response = self.loop.run_until_complete(requester.response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Observe base request did not succede")
        self.assertEqual(response.payload, b'test data 1', "Observe base request gave unexpected result")

        put(b'test data 2')

        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(observation_results, [b'test data 2'])

        notinterested()

    @no_warnings
    def test_lingering(self):
        """Simulate what happens when a request is sent with an observe option,
        but the code only waits for the response and does not subscribe to the
        observation."""
        yieldfrom = self.loop.run_until_complete

        request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.servernetloc
        request.opt.uri_path = ['deep', 'count']
        request.opt.observe = 0

        requester = self.client.request(request)

        response = self.loop.run_until_complete(requester.response)
        del requester, response
        gc.collect()

        # this needs to happen now and not in a precise_warnings because by the
        # time precise_warnings checks the messages, the context was already
        # shut down, but we want to make sure the warning is raised in time.
        self.assertWarned("Observation deleted without explicit cancellation")

    @no_warnings
    def test_unknownhost(self):
        yieldfrom = self.loop.run_until_complete

        request = aiocoap.Message(code=aiocoap.GET, uri="coap://cant.resolve.this.example./empty", observe=0)
        requester = self.client.request(request)

        events = []

        def cb(x):
            events.append("Callback: %s"%x)
        def eb(x):
            events.append("Errback")
        requester.observation.register_callback(cb)
        requester.observation.register_errback(eb)

        response = yieldfrom(requester.response_nonraising)

        self.assertEqual(events, ["Errback"])

    def _test_no_observe(self, path):
        yieldfrom = self.loop.run_until_complete

        m = aiocoap.Message(code=aiocoap.GET, observe=0)
        m.unresolved_remote = self.servernetloc
        m.opt.uri_path = path

        request = self.client.request(m)

        response = yieldfrom(request.response)

        self.assertEqual(response.opt.observe, None)

        return request

    @no_warnings
    def test_notreally(self):
        self._test_no_observe(['deep', 'notreally'])

    @no_warnings
    def test_failure(self):
        request = self._test_no_observe(['deep', 'failure'])

        errors = []
        request.observation.register_errback(errors.append)
        self.assertEqual(len(errors), 1, "Errback was not called on a failed observation")

if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_observe`
    run_fixture_as_standalone_server(WithObserveTestServer)
