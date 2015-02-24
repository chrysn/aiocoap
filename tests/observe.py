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
import unittest

from aiocoap.resource import ObservableResource
from .server import WithTestServer, WithClient, no_warnings, ReplacingResource, MultiRepresentationResource

class ObservableCounter(ObservableResource):
    def __init__(self):
        super(ObservableCounter, self).__init__()
        self.count = 0

    def increment(self):
        self.count += 1
        self.updated_state()

    @asyncio.coroutine
    def render_get(self, request):
        return aiocoap.Message(code=aiocoap.CONTENT, payload=str(self.count).encode('ascii'))

class ObservableReplacingResource(ReplacingResource, ObservableResource):
    @asyncio.coroutine
    def render_put(self, request):
        result = yield from super(ObservableReplacingResource, self).render_put(request)

        self.updated_state()

        return result

class ObserveTestingSite(aiocoap.resource.Site):
    def __init__(self):
        super(ObserveTestingSite, self).__init__()

        self.counter = ObservableCounter()

        self.add_resource(('unobservable',), MultiRepresentationResource())
        self.add_resource(('count',), self.counter)
        self.add_resource(('echo',), ObservableReplacingResource())

class WithObserveTestServer(WithTestServer):
    def create_testing_site(self):
        self.testingsite = ObserveTestingSite()
        return self.testingsite

class TestObserve(WithObserveTestServer, WithClient):
    @no_warnings
    def test_normal_get(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.opt.uri_path = ['count']
        request.unresolved_remote = self.servernetloc

        response = self.loop.run_until_complete(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Normal request did not succede")
        self.assertEqual(response.payload, b'0', "Normal request gave unexpected result")

    def build_observer(self, path):
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

        requester, observation_results, notinterested = self.build_observer(['unobservable'])

        response = self.loop.run_until_complete(requester.response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Unobservable base request did not succede")
        self.assertEqual(response.payload, b'', "Unobservable base request gave unexpected result")

        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(str(observation_results), '[NotObservable()]')

    @no_warnings
    def test_counter(self):
        yieldfrom = self.loop.run_until_complete

        requester, observation_results, notinterested = self.build_observer(['count'])

        response = self.loop.run_until_complete(requester.response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Observe base request did not succede")
        self.assertEqual(response.payload, b'0', "Observe base request gave unexpected result")

        self.testingsite.counter.increment()
        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(observation_results, [b'1'])

        self.testingsite.counter.increment()
        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(observation_results, [b'1', b'2'])

    @no_warnings
    def test_echo(self):
        yieldfrom = self.loop.run_until_complete

        def put(b):
            m = aiocoap.Message(code=aiocoap.PUT, payload=b)
            m.unresolved_remote = self.servernetloc
            m.opt.uri_path = ['echo']
            response = yieldfrom(self.client.request(m).response)
            self.assertEqual(response.code, aiocoap.CHANGED)

        put(b'test data 1')

        requester, observation_results, notinterested = self.build_observer(['echo'])
        response = self.loop.run_until_complete(requester.response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Observe base request did not succede")
        self.assertEqual(response.payload, b'test data 1', "Observe base request gave unexpected result")

        put(b'test data 2')

        yieldfrom(asyncio.sleep(0.1))
        self.assertEqual(observation_results, [b'test data 2'])
