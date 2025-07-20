# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests for resource observation

Note that cancellation of observations is checked in neither way; that's
largely because the implementation has fallen behind on the drafts anyway and
needs to be updated."""

import asyncio
import aiocoap
from aiocoap.numbers import ContentFormat
import gc
import unittest

from aiocoap.resource import ObservableResource, WKCResource
from .test_server import (
    WithTestServer,
    WithClient,
    no_warnings,
    ReplacingResource,
    MultiRepresentationResource,
)
from .common import run_fixture_as_standalone_server


class ObservableCounter(ObservableResource):
    def __init__(self, number_formatter=lambda x: x):
        super(ObservableCounter, self).__init__()
        self.count = 0
        self.number_formatter = number_formatter

    async def render_delete(self, request):
        self.count = 0
        self.updated_state()
        return aiocoap.Message(code=aiocoap.CHANGED)

    async def render_post(self, request):
        if request.payload == b"double":
            # Calling updated_state() twice without yielding inbetween is key
            # here; this ensures that Futures are not treated carelessly.
            self.count += 1
            # Triggering with explicit value because if left empty, the value
            # would be synthesized after the next yielding anyway, and no
            # ill-effects would be visible.
            self.updated_state(
                aiocoap.Message(
                    code=aiocoap.CONTENT,
                    payload=str(self.number_formatter(self.count)).encode("ascii"),
                )
            )
        self.count += 1
        self.updated_state()
        return aiocoap.Message(code=aiocoap.CHANGED)

    async def render_get(self, request):
        return aiocoap.Message(
            code=aiocoap.CONTENT,
            payload=str(self.number_formatter(self.count)).encode("ascii"),
        )

    async def render_fetch(self, request):
        return aiocoap.Message(
            code=aiocoap.CONTENT,
            payload=(
                "%s; request had length %s"
                % (self.number_formatter(self.count), len(request.payload))
            ).encode("ascii"),
        )


class ObservableReplacingResource(ReplacingResource, ObservableResource):
    async def render_put(self, request):
        result = await super(ObservableReplacingResource, self).render_put(request)

        self.updated_state()

        return result


class ObserveLateUnbloomer(ObservableResource):
    """A resource that accepts the server observation at first but at rendering
    time decides it can't do it"""

    def __init__(self):
        super().__init__()
        self._cancel_right_away = []

    async def add_observation(self, request, serverobservation):
        self._cancel_right_away.append(
            lambda: serverobservation.deregister("Changed my mind at render time")
        )
        serverobservation.accept(lambda: None)

    async def render_get(self, request):
        while self._cancel_right_away:
            self._cancel_right_away.pop(0)()
        return aiocoap.Message()


class ObservableFailure(ObservableResource):
    async def render_get(self, request):
        return aiocoap.Message(code=aiocoap.UNAUTHORIZED)


class ObserveTestingSite(aiocoap.resource.Site):
    prefix = []

    def __init__(self):
        super(ObserveTestingSite, self).__init__()

        self.add_resource(
            self.prefix + ["unobservable"],
            MultiRepresentationResource(
                {
                    ContentFormat.TEXT: b"",
                }
            ),
        )
        self.add_resource(self.prefix + ["count"], ObservableCounter())
        self.add_resource(self.prefix + ["echo"], ObservableReplacingResource())
        self.add_resource(self.prefix + ["notreally"], ObserveLateUnbloomer())
        self.add_resource(self.prefix + ["failure"], ObservableFailure())
        self.add_resource(
            self.prefix + ["large"], ObservableCounter(lambda x: (" %3d" % x) * 400)
        )


class NestedSite(aiocoap.resource.Site):
    def __init__(self):
        super().__init__()

        # Not part of the test suite, but handy when running standalone
        self.add_resource(
            [".well-known", "core"], WKCResource(self.get_resources_as_linkheader)
        )

        self.subsite = ObserveTestingSite()

        self.add_resource(["deep"], self.subsite)


class UnnestedSite(ObserveTestingSite):
    prefix = ["deep"]


class WithObserveTestServer(WithTestServer):
    def create_testing_site(self):
        self.testingsite = NestedSite()
        # use this when you suspect that things go wrong due to nesting;
        # usually not running this because it has no way to fail without nested
        # failing too
        # self.testingsite = UnnestedSite()
        return self.testingsite


class TestObserve(WithObserveTestServer, WithClient):
    @no_warnings
    async def test_normal_get(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.opt.uri_path = ["deep", "count"]
        request.unresolved_remote = self.servernetloc

        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "Normal request did not succede"
        )
        self.assertEqual(
            response.payload, b"0", "Normal request gave unexpected result"
        )

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

        async def task():
            try:
                async for obs in requester.observation:
                    observation_results.append(obs.payload)
                # This is how non-observability is indicated: The loop just terminates
                observation_results.append("done")
            except Exception as e:
                observation_results.append(e)

        running_task = asyncio.create_task(task())

        return requester, observation_results, running_task.cancel

    @no_warnings
    async def test_unobservable(self):
        requester, observation_results, notinterested = self.build_observer(
            ["deep", "unobservable"]
        )

        response = await requester.response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "Unobservable base request did not succede"
        )
        self.assertEqual(
            response.payload, b"", "Unobservable base request gave unexpected result"
        )

        await asyncio.sleep(0.1)
        self.assertEqual(observation_results, ["done"])

    async def _change_counter(self, method, payload, path=["deep", "count"]):
        request = aiocoap.Message(code=method, uri_path=path, payload=payload)
        request.unresolved_remote = self.servernetloc
        await self.client.request(request).response_raising

    async def _test_counter(
        self, baserequest, formatter, postpayload=b"", path=["deep", "count"]
    ):
        """Run a counter test with requests built from baserequest. Expect
        response payloads to be equal to the formatter(n) for n being the
        counter value"""
        await self._change_counter(aiocoap.DELETE, b"", path=path)

        requester, observation_results, notinterested = self.build_observer(
            path, baserequest=baserequest
        )

        response = await requester.response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "Observe base request did not succede"
        )
        self.assertEqual(
            response.payload,
            formatter(0),
            "Observe base request gave unexpected result",
        )

        await self._change_counter(aiocoap.POST, postpayload, path=path)
        await asyncio.sleep(0.1)
        self.assertEqual(observation_results, [formatter(1)])

        await self._change_counter(aiocoap.POST, postpayload, path=path)
        await asyncio.sleep(0.1)
        self.assertEqual(observation_results, [formatter(1), formatter(2)])

        notinterested()

    @no_warnings
    async def test_counter(self):
        await self._test_counter(None, lambda x: str(x).encode("ascii"))

    @no_warnings
    async def test_counter_blockwise(self):
        await self._test_counter(
            None,
            lambda x: str((" %3d" % x) * 400).encode("ascii"),
            path=["deep", "large"],
        )

    @no_warnings
    async def test_counter_fetch(self):
        await self._test_counter(
            aiocoap.Message(code=aiocoap.FETCH, payload=b"12345"),
            lambda x: ("%s; request had length 5" % x).encode("ascii"),
        )

    # Test hard disabled because not only it expects failure, but that failure
    # also causes protocol GC issues. Tracked in
    # https://github.com/chrysn/aiocoap/issues/95
    #     @no_warnings
    #     async def test_counter_fetch_big(self):
    #         await self._test_counter(
    #                 aiocoap.Message(code=aiocoap.FETCH, payload=b'12345' * 1000),
    #                 lambda x: ('%s; request had length 5000'%x).encode('ascii'))

    @no_warnings
    async def test_counter_double(self):
        # see comments on b"double" in render_post
        await self._test_counter(None, lambda x: str(x * 2).encode("ascii"), b"double")

    @no_warnings
    async def test_echo(self):
        async def put(b):
            m = aiocoap.Message(code=aiocoap.PUT, payload=b)
            m.unresolved_remote = self.servernetloc
            m.opt.uri_path = ["deep", "echo"]
            response = await self.client.request(m).response
            self.assertEqual(response.code, aiocoap.CHANGED)

        await put(b"test data 1")

        requester, observation_results, notinterested = self.build_observer(
            ["deep", "echo"]
        )
        response = await requester.response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "Observe base request did not succede"
        )
        self.assertEqual(
            response.payload,
            b"test data 1",
            "Observe base request gave unexpected result",
        )

        await put(b"test data 2")

        await asyncio.sleep(0.1)
        self.assertEqual(observation_results, [b"test data 2"])

        notinterested()

    @unittest.expectedFailure  # regression since 82b35c1f8f, tracked as
    @no_warnings  # https://github.com/chrysn/aiocoap/issues/104
    async def test_lingering(self):
        """Simulate what happens when a request is sent with an observe option,
        but the code only waits for the response and does not subscribe to the
        observation."""
        request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.servernetloc
        request.opt.uri_path = ["deep", "count"]
        request.opt.observe = 0

        requester = self.client.request(request)

        response = await requester.response
        del requester, response
        gc.collect()

        # this needs to happen now and not in a precise_warnings because by the
        # time precise_warnings checks the messages, the context was already
        # shut down, but we want to make sure the warning is raised in time.
        self.assertWarned("Observation deleted without explicit cancellation")

    @no_warnings
    async def test_unknownhost(self):
        request = aiocoap.Message(
            code=aiocoap.GET, uri="coap://cant.resolve.this.example./empty", observe=0
        )
        requester = self.client.request(request)

        events = []

        async def task():
            try:
                async for obs in requester.observation:
                    events.append("Callback: %s" % obs.payload)
                events.append("Regular empty return")
            except Exception as e:
                events.append("Error %s" % type(e).__name__)

        pull_task = asyncio.create_task(task())

        response = await requester.response_nonraising
        await asyncio.sleep(0.1)
        pull_task.cancel()

        self.assertEqual(events, ["Error ResolutionError"])

    @no_warnings
    async def test_late_subscription_eventual_consistency(self):
        await self._change_counter(aiocoap.DELETE, b"")

        request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.servernetloc
        request.opt.uri_path = ("deep", "count")
        request.opt.observe = 0

        requester = self.client.request(request)

        first_response = await requester.response
        self.assertEqual(
            first_response.payload, b"0", "Observe base request gave unexpected result"
        )

        await self._change_counter(aiocoap.POST, b"")
        await self._change_counter(aiocoap.POST, b"")

        last_seen = None

        async def task():
            nonlocal last_seen
            async for obs in requester.observation:
                last_seen = obs.payload

        pull_task = asyncio.create_task(task())

        # this is not required in the current implementation as it calls back
        # right from the registration, but i don't want to prescribe that.
        wait_a_moment = asyncio.get_running_loop().create_future()
        asyncio.get_event_loop().call_soon(lambda: wait_a_moment.set_result(None))
        await wait_a_moment

        pull_task.cancel()

        self.assertEqual(last_seen, b"2")
        # only testing what was last seen because both receiving b"1" and b"2"
        # and only b"2" are correct eventually consistent results.

        requester.observation.cancel()

    async def _test_no_observe(self, path):
        m = aiocoap.Message(code=aiocoap.GET, observe=0)
        m.unresolved_remote = self.servernetloc
        m.opt.uri_path = path

        request = self.client.request(m)

        response = await request.response

        self.assertEqual(response.opt.observe, None)

        return request

    @no_warnings
    async def test_notreally(self):
        await self._test_no_observe(["deep", "notreally"])

    @no_warnings
    async def test_failure(self):
        request = await self._test_no_observe(["deep", "failure"])

        failure = None

        async def task():
            nonlocal failure
            try:
                async for obs in requester.observation:
                    pass
            except Exception as e:
                failure = e

        pull_task = asyncio.create_task(task())
        await asyncio.sleep(0.1)

        self.assertTrue(
            failure is not None, "Errback was not called on a failed observation"
        )


if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_observe`
    run_fixture_as_standalone_server(WithObserveTestServer)
