# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
import contextlib
import re
import aiocoap
import aiocoap.resource
from aiocoap.numbers import ContentFormat
import unittest
import os
import json

from . import common
from .fixtures import no_warnings, Destructing, CLEANUPTIME


class slow_empty_ack(contextlib.AsyncContextDecorator):
    async def __aenter__(self):
        # FIXME: Pushing the times here so that even on a loaded system
        # with pypy and coverage, this can complete realistically.
        #
        # This will break as soon as transport tuning becomes more
        # per-transport or even per-remote; the proper fix would be to use
        # mock time anyway.
        self.original_empty_ack_delay = aiocoap.numbers.TransportTuning.EMPTY_ACK_DELAY
        aiocoap.numbers.TransportTuning.EMPTY_ACK_DELAY = (
            0.9 * aiocoap.numbers.TransportTuning.ACK_TIMEOUT
        )
        return self

    async def __aexit__(self, *exc):
        aiocoap.numbers.TransportTuning.EMPTY_ACK_DELAY = self.original_empty_ack_delay
        return False


class MultiRepresentationResource(aiocoap.resource.Resource):
    def __init__(self, representations):
        self._representations = representations
        super().__init__()

    async def render_get(self, request):
        if request.opt.proxy_scheme is not None:
            # For CLI test_noproxy -- but otherwise a symptom of https://github.com/chrysn/aiocoap/issues/268
            return aiocoap.Message(code=aiocoap.CONTENT, payload=b"This is no proxy")

        m = request.opt.accept or ContentFormat.TEXT

        if m in self._representations:
            response = self._representations[m]
        else:
            return aiocoap.Message(code=aiocoap.NOT_ACCEPTABLE)

        return aiocoap.Message(payload=response, content_format=request.opt.accept or 0)


class SlowResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        await asyncio.sleep(0.2)
        # Marking the response as confirmable overrides the default behavior of
        # sending NON responses to NON requests.
        #
        # This is done to aid the test_freeoncancel test, and should revert to
        # the default behavior once that has better control over the environment.
        return aiocoap.Message(transport_tuning=aiocoap.Reliable)


class BigResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        # 10kb
        payload = b"0123456789----------" * 512
        response = aiocoap.Message(payload=payload)

        aiocoap.resource.hashing_etag(request, response)
        return response


class SlowBigResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        # Should be 0.2s usually, but while running in slow_empty_ack mode, we
        # have to slow it down. Adds 2s to the tests, but that makes the test
        # more reliable.
        await asyncio.sleep(aiocoap.numbers.TransportTuning.EMPTY_ACK_DELAY * 1.1)
        # 1.6kb
        payload = b"0123456789----------" * 80
        return aiocoap.Message(payload=payload)


class ManualBigResource(aiocoap.resource.Resource):
    async def needs_blockwise_assembly(self, request):
        return False

    async def render_get(self, request):
        BlockwiseTuple = aiocoap.optiontypes.BlockOption.BlockwiseTuple
        block2 = request.opt.block2 or BlockwiseTuple(0, 0, 6)
        # as above
        body = b"0123456789----------" * 80
        # in a more realistic example, we wouldn't build this in memory but eg.
        # seek and read limited length
        slice = body[block2.start :]
        more = len(slice) > block2.size
        slice = slice[: block2.size]
        block2 = BlockwiseTuple(block2.block_number, more, block2.size_exponent)
        return aiocoap.Message(payload=slice, block2=block2)


class ReplacingResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(payload=self.value)

    async def render_put(self, request):
        self.value = request.payload.replace(b"0", b"O")
        return aiocoap.Message()

    async def render_post(self, request):
        response = request.payload.replace(b"0", b"O")
        return aiocoap.Message(code=aiocoap.CONTENT, payload=response)


class RootResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(
            code=aiocoap.CONTENT, payload=b"Welcome to the test server"
        )


class GenericErrorResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        raise RuntimeError()


class PrettyErrorResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        raise self.MyError()

    class MyError(aiocoap.error.ConstructionRenderableError):
        code = aiocoap.NOT_FOUND
        message = "I'm sorry nothing is here"


class DoubleErrorResource(aiocoap.resource.Resource):
    async def render_get(self, request):
        raise self.MyError()

    class MyError(aiocoap.error.RenderableError):
        def to_message(self):
            raise RuntimeError()


class CreateForLocation(aiocoap.resource.Resource):
    async def render_post(self, request):
        return aiocoap.Message(
            code=aiocoap.CREATED,
            location_path=["create", "here", ""],
            location_query=["this=this", "that=that"],
        )


class WhoAmI(aiocoap.resource.Resource):
    async def render_get(self, request):
        p = dict(
            repr=repr(request.remote),
            hostinfo=request.remote.hostinfo,
            hostinfo_local=request.remote.hostinfo_local,
            scheme=request.remote.scheme,
            urihost_option=request.opt.uri_host,
            # FIXME: The whole get_request_uri is a mess
            requested_uri=request._original_request_uri,
            claims=request.remote.authenticated_claims,
        )
        return aiocoap.Message(
            code=aiocoap.CONTENT,
            content_format=ContentFormat.JSON,
            payload=json.dumps(p).encode("utf8"),
        )


class BasicTestingSite(aiocoap.resource.Site):
    def __init__(self):
        super(BasicTestingSite, self).__init__()

        # Not part of the test suite, but handy when running standalone
        self.add_resource(
            [".well-known", "core"],
            aiocoap.resource.WKCResource(self.get_resources_as_linkheader),
        )

        self.add_resource(
            ["empty"],
            MultiRepresentationResource(
                {
                    ContentFormat.JSON: b"{}",
                    ContentFormat.LINKFORMAT: b"<>",
                    ContentFormat.TEXT: b"",
                }
            ),
        )
        self.add_resource(
            ["answer"],
            MultiRepresentationResource(
                {
                    ContentFormat.JSON: b'{"answer": 42}',
                    ContentFormat.CBOR: b"\xa1\x66\x61\x6e\x73\x77\x65\x72\x18\x2a",
                    ContentFormat.LINKFORMAT: b'<data:text/plain;42>;rel="answer";anchor="https://en.wikipedia.org/wiki/Phrases_from_The_Hitchhiker%27s_Guide_to_the_Galaxy#Answer_to_the_Ultimate_Question_of_Life,_the_Universe,_and_Everything_(42)"',
                    ContentFormat.TEXT: b"The answer to life, the universe, and everything is 42.",
                }
            ),
        )
        self.add_resource(["slow"], SlowResource())
        self.add_resource(["big"], BigResource())
        self.add_resource(["slowbig"], SlowBigResource())
        self.add_resource(["manualbig"], ManualBigResource())
        self.add_resource(["replacing"], self.Subsite())
        self.add_resource(["error", "generic"], GenericErrorResource())
        self.add_resource(["error", "pretty"], PrettyErrorResource())
        self.add_resource(["error", "double"], DoubleErrorResource())
        self.add_resource(["create", ""], CreateForLocation())
        self.add_resource(["whoami"], WhoAmI())
        self.add_resource([], RootResource())

    class Subsite(aiocoap.resource.Site):
        def __init__(self):
            super().__init__()
            self.add_resource(["one"], ReplacingResource())


class WithTestServer(Destructing):
    # to allow overriding the factory class
    TestingSite = BasicTestingSite

    def create_testing_site(self):
        return self.TestingSite()

    def get_server_ssl_context(self):
        """Override hook for subclasses that want to populate _ssl_context at construction"""
        return None

    async def asyncSetUp(self):
        await super().asyncSetUp()

        multicastif = (
            os.environ["AIOCOAP_TEST_MCIF"].split(":")
            if "AIOCOAP_TEST_MCIF" in os.environ
            else []
        )

        self.server = await aiocoap.Context.create_server_context(
            self.create_testing_site(),
            bind=(self.serveraddress, None),
            multicast=multicastif,
            _ssl_context=self.get_server_ssl_context(),
        )

    async def asyncTearDown(self):
        await super().asyncTearDown()

        # let the server receive the acks we just sent
        await asyncio.sleep(CLEANUPTIME)
        await self.server.shutdown()
        # Nothing in the context should keep the request interfaces alive;
        # delete them first to see *which* of them is the one causing the
        # trouble
        while self.server.request_interfaces:
            await self._del_to_be_sure(
                {
                    "get": (lambda self: self.server.request_interfaces[0]),
                    "del": (lambda self: self.server.request_interfaces.__delitem__(0)),
                    "label": "self.request_interfaces[%s]"
                    % self.server.request_interfaces[0],
                }
            )
        await self._del_to_be_sure("server")

        super(WithTestServer, self).tearDown()

    serveraddress = "::1"
    servernetloc = "[%s]" % serveraddress
    servernamealias = common.loopbackname_v6 or common.loopbackname_v46


class WithClient(Destructing):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.test_did_shut_down_client = False

        self.client = await aiocoap.Context.create_client_context()

    async def asyncTearDown(self):
        await super().asyncTearDown()

        if not self.test_did_shut_down_client:
            self.test_did_shut_down_client = False
            await asyncio.sleep(CLEANUPTIME)
            await self.client.shutdown()

        # Nothing in the context should keep the request interfaces alive;
        # delete them first to see *which* of them is the one causing the
        # trouble
        while self.client.request_interfaces:
            await self._del_to_be_sure(
                {
                    "get": (lambda self: self.client.request_interfaces[0]),
                    "del": (lambda self: self.client.request_interfaces.__delitem__(0)),
                    "label": "self.client.request_interfaces[0] which is %s"
                    % self.client.request_interfaces[0],
                }
            )

        await self._del_to_be_sure("client")

        super(WithClient, self).tearDown()


# test cases


class TestServerBase(WithTestServer, WithClient):
    """All the tools for building requests, but no actual tests; use this when
    working off the test server with no intention to to the full set of
    tests."""

    @no_warnings
    def build_request(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.servernetloc
        return request


class TestServer(TestServerBase):
    @no_warnings
    async def test_empty_accept(self):
        request = self.build_request()
        request.opt.uri_path = ["empty"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "Simple request did not succeed"
        )
        self.assertEqual(response.payload, b"", "Simple request gave unexpected result")

    @no_warnings
    async def test_unacceptable_accept(self):
        request = self.build_request()
        request.opt.uri_path = ["empty"]
        request.opt.accept = 9999
        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.NOT_ACCEPTABLE,
            "Inacceptable request was not not accepted",
        )

    @no_warnings
    async def test_js_accept(self):
        request = self.build_request()
        request.opt.uri_path = ["empty"]
        request.opt.accept = ContentFormat.JSON
        response = await self.client.request(request).response
        self.assertEqual(response.code, aiocoap.CONTENT, "JSON request did not succeed")
        self.assertEqual(response.payload, b"{}", "JSON request gave unexpected result")

    @no_warnings
    async def test_nonexisting_resource(self):
        request = self.build_request()
        request.opt.uri_path = ["nonexisting"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.NOT_FOUND, "Nonexisting resource was not not found"
        )

    @no_warnings
    async def test_spurious_resource(self):
        request = self.build_request()
        request.opt.uri_path = ["..", "empty"]
        response = await self.client.request(request).response
        # different behavior would be ok-ish, as the .. in the request is forbidden, but returning 4.04 is sane here
        self.assertEqual(
            response.code,
            aiocoap.NOT_FOUND,
            "'..' component in path did not get ignored the way it was expected",
        )

    @no_warnings
    @slow_empty_ack()
    async def test_fast_resource(self):
        request = self.build_request()
        request.opt.uri_path = ["empty"]

        response = await self.client.request(request).response

        self.assertEqual(response.code, aiocoap.CONTENT, "Fast request did not succeed")
        self.assertEqual(self._count_empty_acks(), 0, "Fast resource had an empty ack")

    @no_warnings
    async def test_slow_resource(self):
        request = self.build_request()
        request.opt.uri_path = ["slow"]

        response = await self.client.request(request).response

        self.assertEqual(response.code, aiocoap.CONTENT, "Slow request did not succeed")
        if response.requested_scheme in (None, "coap"):
            self.assertEqual(
                self._count_empty_acks(),
                1,
                "Slow resource was not handled in two exchanges",
            )

    @no_warnings
    async def test_big_resource(self):
        request = self.build_request()
        request.opt.uri_path = ["big"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "Big resource request did not succeed"
        )
        self.assertEqual(
            len(response.payload), 10240, "Big resource is not as big as expected"
        )

        self.assertTrue(
            response.opt.etag != None, "Big resource does not provide an ETag"
        )

        request = self.build_request()
        request.opt.uri_path = ["big"]
        request.opt.etags = [response.opt.etag]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.VALID,
            "Big resource does not support ETag validation",
        )
        self.assertTrue(
            response.opt.etag != None, "Big resource does not send ETag for validation"
        )

    @no_warnings
    @slow_empty_ack()
    async def test_slowbig_resource(self):
        request = self.build_request()
        request.opt.uri_path = ["slowbig"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "SlowBig resource request did not succeed"
        )
        self.assertEqual(
            len(response.payload), 1600, "SlowBig resource is not as big as expected"
        )
        if response.requested_scheme in (None, "coap"):
            self.assertEqual(
                self._count_empty_acks(),
                1,
                "SlowBig resource was not handled in two exchanges",
            )

    @no_warnings
    async def test_manualbig_resource(self):
        request = self.build_request()
        request.opt.uri_path = ["manualbig"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.CONTENT, "ManualBig resource request did not succeed"
        )
        self.assertEqual(
            len(response.payload), 1600, "ManualBig resource is not as big as expected"
        )

    @no_warnings
    async def test_replacing_resource(self):
        testpattern = b"01" * 1024

        request = self.build_request()
        request.code = aiocoap.PUT
        request.payload = testpattern
        request.opt.uri_path = ["replacing", "one"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.CHANGED, "PUT did not result in CHANGED"
        )
        self.assertEqual(response.payload, b"", "PUT has unexpected payload")

        request = self.build_request()
        request.code = aiocoap.GET
        request.opt.uri_path = ["replacing", "one"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.CONTENT,
            "Replacing resource could not be GOT (GET'd?) successfully",
        )
        self.assertEqual(
            response.payload,
            testpattern.replace(b"0", b"O"),
            "Replacing resource did not replace as expected between PUT and GET",
        )

        request = self.build_request()
        request.code = aiocoap.POST
        request.payload = testpattern
        request.opt.uri_path = ["replacing", "one"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.CONTENT,
            "Replacing resource could not be POSTed to successfully",
        )
        self.assertEqual(
            response.payload,
            testpattern.replace(b"0", b"O"),
            "Replacing resource did not replace as expected when POSTed",
        )

    async def test_error_resources(self):
        request = self.build_request()
        request.opt.uri_path = ["error", "generic"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.INTERNAL_SERVER_ERROR,
            "Runtime error possibly leaking information",
        )
        self.assertEqual(
            response.payload, b"", "Runtime error possibly leaking information"
        )

        request = self.build_request()
        request.opt.uri_path = ["error", "pretty"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.NOT_FOUND,
            "Runtime error possibly leaking information",
        )
        self.assertTrue(
            response.payload.decode("ascii").startswith("I'm sorry"),
            "Runtime error possibly leaking information",
        )

        request = self.build_request()
        request.opt.uri_path = ["error", "double"]
        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.INTERNAL_SERVER_ERROR,
            "Runtime double error possibly leaking information",
        )
        self.assertEqual(
            response.payload, b"", "Runtime double error possibly leaking information"
        )

    @no_warnings
    async def test_root_resource(self):
        request = self.build_request()
        request.opt.uri_path = []
        response = await self.client.request(request).response
        self.assertEqual(response.code, aiocoap.CONTENT, "Root resource was not found")

    _empty_ack_logmsg = re.compile(
        "^Incoming message <aiocoap.Message: EMPTY from .*, ACK"
    )

    def _count_empty_acks(self):
        # only client-side received empty-acks are counted; they typically
        # generate an empty ack back when the separate response is ack'd.
        return sum(
            self._empty_ack_logmsg.match(x.msg) is not None
            for x in self.handler
            if x.name != "coap-server"
        )

    @no_warnings
    async def test_clean_shutdown(self):
        await self.client.shutdown()
        self.test_did_shut_down_client = True

        request = self.build_request()
        # This is clearly misuse of the API, but nonetheless, only a
        # LibraryShutdown should fly out of it.
        #
        # Ideally, we'd do that "during" shutdown", but that's terribly racy
        # business, both wins are acceptable (what if the shutdown hasn't
        # really begun yet), and it's highly unlikely that we hit the juicy
        # cases.
        with self.assertRaises(aiocoap.error.LibraryShutdown):
            await self.client.request(request).response


@unittest.skipIf(common.tcp_disabled, "TCP disabled in environment")
class TestServerTCP(TestServer):
    # no modification in server setup necessary, as by default, all transports
    # are enabled on servers.

    def build_request(self):
        request = super().build_request()
        request.requested_scheme = "coap+tcp"
        return request


ws_modules = aiocoap.defaults.ws_missing_modules()


@unittest.skipIf(
    ws_modules or common.ws_disabled,
    "WS missing modules (%s) or disabled in this environment" % (ws_modules,),
)
class TestServerWS(TestServer):
    # as with TestServerWS

    def build_request(self):
        request = super().build_request()
        # odd default port
        request.unresolved_remote += ":8683"
        request.requested_scheme = "coap+ws"
        return request


if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_server`
    common.run_fixture_as_standalone_server(WithTestServer)
