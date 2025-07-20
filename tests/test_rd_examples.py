# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This test runs a resource directory and executes the examples from the RD
specification against it.
"""

import unittest

import aiocoap
from aiocoap.util import hostportjoin

from .test_server import Destructing, WithClient

linkheader_modules = aiocoap.defaults.linkheader_missing_modules()
_skip_unless_linkheader = unittest.skipIf(
    linkheader_modules,
    "Modules missing for running RD tests: %s" % (linkheader_modules,),
)
if not linkheader_modules:
    from aiocoap.util.linkformat import link_header
    import aiocoap.cli.rd


class WithResourceDirectory(Destructing):
    rd_address = "::1"
    rd_port = 56830
    rd_netloc = "[%s]:%d" % (rd_address, rd_port)

    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.rd = aiocoap.cli.rd.Main(["--bind", hostportjoin("::1", self.rd_port)])
        await self.rd.initializing

    async def asyncTearDown(self):
        await self.rd.shutdown()
        await super().asyncTearDown()

        await self._del_to_be_sure("rd")


class TestDiscovery(WithResourceDirectory, WithClient):
    @_skip_unless_linkheader
    async def test_discovery(self):
        request = aiocoap.Message(
            code=aiocoap.GET,
            uri="coap://%s/.well-known/core?rt=core.rd*" % self.rd_netloc,
        )
        response = await self.client.request(request).response

        self.assertEqual(
            response.code, aiocoap.CONTENT, "RD discovery did not give content"
        )
        links = link_header.parse(response.payload.decode("utf8"))
        # Not checking for presence of group resources: not implemented here
        for rt in ("core.rd", "core.rd-lookup-ep", "core.rd-lookup-res"):
            self.assertEqual(
                len([x for x in links.links if x.rt == [rt]]),
                1,
                "Not exactly one entry of rt=%s found" % rt,
            )

    async def _get_endpoint(self, rt):
        """Return the URI for a given rt in the configured RD"""

        if not hasattr(self, "_endpoints"):
            request = aiocoap.Message(
                code=aiocoap.GET,
                uri="coap://%s/.well-known/core?rt=core.rd*" % self.rd_netloc,
            )
            response = await self.client.request(request).response

            self._endpoints = {
                entry.rt[0]: entry.get_target(response.get_request_uri())
                for entry in link_header.parse(response.payload.decode("utf8")).links
            }

        return self._endpoints[rt]

    @_skip_unless_linkheader
    async def test_registration(self):
        request = aiocoap.Message(
            code=aiocoap.POST,
            uri=(await self._get_endpoint("core.rd")) + "?ep=node1",
            content_format=40,
            payload=b'</sensors/temp>;ct=41;rt="temperature-c";if="sensor",</sensors/light>;ct=41;rt="light-lux";if="sensor"',
        )
        response = await self.client.request(request).response

        self.assertEqual(
            response.code, aiocoap.CREATED, "Registration did not result in Created"
        )
        self.assertTrue(
            len(response.opt.location_path) > 0,
            "Registration did not result in non-empty registration resource",
        )

    # FIXME: there are many more things to be tested here
