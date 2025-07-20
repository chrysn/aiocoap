# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
import unittest

from . import common
from .test_server import (
    Destructing,
    WithClient,
    WithTestServer,
    CLEANUPTIME,
)
import aiocoap.proxy.client
import aiocoap.cli.proxy
from aiocoap.util import hostportjoin


class WithReverseProxy(Destructing):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.reverseproxy = aiocoap.cli.proxy.Main(
            [
                "--reverse",
                "--bind",
                hostportjoin(self.proxyhost, self.proxyport),
                "--namebased",
                "%s:%s" % (self.name_for_real_server, self.servernetloc),
                "--pathbased",
                "%s:%s" % ("/".join(self.path_for_real_server), self.servernetloc),
            ],
        )
        await self.reverseproxy.initializing

    async def asyncTearDown(self):
        await self.reverseproxy.shutdown()
        await self._del_to_be_sure("reverseproxy")
        await asyncio.sleep(CLEANUPTIME)
        await super().asyncTearDown()

    proxyport = 56839
    proxyhost = common.loopbackname_v6 or common.loopbackname_v46
    proxyaddress = "%s:%d" % (proxyhost, proxyport)

    name_for_real_server = "aliasedname"
    path_for_real_server = ("aliased", "name")


class TestReverseProxy(WithReverseProxy, WithClient, WithTestServer):
    @unittest.skipIf(
        common.using_simple6,
        "Some proxy tests fail with simple6 (https://github.com/chrysn/aiocoap/issues/88)",
    )
    async def test_routing(self):
        def req():
            request = aiocoap.Message(code=aiocoap.GET)
            request.unresolved_remote = self.proxyaddress
            request.opt.uri_path = ("big",)
            return request

        request = req()

        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.BAD_REQUEST,
            "GET without hostname gave resource (something like BAD_REQUEST expected)",
        )

        request = req()
        request.opt.uri_host = self.name_for_real_server

        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.CONTENT,
            "GET with hostname based proxying was not successful)",
        )

        request = req()
        request.opt.uri_path = self.path_for_real_server + request.opt.uri_path

        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.CONTENT,
            "GET with path based proxying was not successful)",
        )

    @unittest.skipIf(
        common.using_simple6,
        "Some proxy tests fail with simple6 (https://github.com/chrysn/aiocoap/issues/88)",
    )
    async def test_options(self):
        def req():
            request = aiocoap.Message(code=aiocoap.GET)
            request.unresolved_remote = self.proxyaddress
            request.opt.uri_path = ("big",)
            request.opt.uri_host = self.name_for_real_server
            return request

        request = req()

        request.opt.proxy_scheme = "coap"

        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.BAD_OPTION,
            "Reverse proxy supports proxying even though it shouldn't.",
        )

        request = req()
        request.opt.add_option(
            aiocoap.optiontypes.StringOption(2**10 + 2, "can't proxy this")
        )

        response = await self.client.request(request).response
        self.assertEqual(
            response.code, aiocoap.BAD_OPTION, "Proxy did not react to unsafe option."
        )

        request = req()
        request.opt.add_option(
            aiocoap.optiontypes.StringOption(2**10, "nothing to see here")
        )

        response = await self.client.request(request).response
        self.assertEqual(
            response.code,
            aiocoap.CONTENT,
            "Proxy did not ignore to safe-to-forward option.",
        )
