# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This test runs a resource directory and executes the examples from the RD
specification against it.
"""

import asyncio
import unittest

import aiocoap

from .test_server import WithAsyncLoop, Destructing, WithClient

linkheader_modules = aiocoap.defaults.linkheader_missing_modules()
_skip_unless_linkheader = unittest.skipIf(linkheader_modules, "Modules missing for running RD tests: %s"%(linkheader_modules,))
if not linkheader_modules:
    import link_header
    import aiocoap.cli.rd

class WithResourceDirectory(WithAsyncLoop, Destructing):
    rd_address = '::1'
    rd_port = 56830
    rd_netloc = '[%s]:%d'%(rd_address, rd_port)

    def setUp(self):
        super().setUp()

        yieldfrom = lambda f: self.loop.run_until_complete(f)

        self.rd = aiocoap.cli.rd.Main(['--server-address', '::1', '--server-port', str(self.rd_port)])
        yieldfrom(self.rd.initializing)

    def tearDown(self):
        self.loop.run_until_complete(self.rd.shutdown())
        super().tearDown()

        self._del_to_be_sure('rd')

class TestDiscovery(WithResourceDirectory, WithClient):
    @_skip_unless_linkheader
    def test_discovery(self):
        yieldfrom = lambda f: self.loop.run_until_complete(f)

        request = aiocoap.Message(code=aiocoap.GET, uri='coap://%s/.well-known/core?rt=core.rd*'%self.rd_netloc)
        response = yieldfrom(self.client.request(request).response)

        self.assertEqual(response.code, aiocoap.CONTENT, "RD discovery did not give content")
        links = link_header.parse(response.payload.decode('utf8'))
        for rt in ('core.rd', 'core.rd-lookup-ep', 'core.rd-lookup-res', 'core.rd-lookup-gp', 'core.rd-group'):
            self.assertEqual(len([x for x in links.links if x.rt == [rt]]), 1, "Not exactly one entry of rt=%s found"%rt)

    @asyncio.coroutine
    def _get_endpoint(self, rt):
        """Return the URI for a given rt in the configured RD"""

        if not hasattr(self, '_endpoints'):
            request = aiocoap.Message(code=aiocoap.GET, uri='coap://%s/.well-known/core?rt=core.rd*'%self.rd_netloc)
            response = yield from self.client.request(request).response

            self._endpoints = {entry.rt[0]: entry.get_target(response.get_request_uri())
                    for entry
                    in link_header.parse(response.payload.decode('utf8')).links
                    }

        return self._endpoints[rt]

    @_skip_unless_linkheader
    def test_registration(self):
        yieldfrom = lambda f: self.loop.run_until_complete(f)

        request = aiocoap.Message(
                code=aiocoap.POST,
                uri=yieldfrom(self._get_endpoint('core.rd')) + '?ep=node1',
                content_format=40,
                payload=b'</sensors/temp>;ct=41;rt="temperature-c";if="sensor",</sensors/light>;ct=41;rt="light-lux";if="sensor"',
                )
        response = yieldfrom(self.client.request(request).response)

        self.assertEqual(response.code, aiocoap.CREATED, "Registration did not result in Created")
        self.assertTrue(len(response.opt.location_path) > 0, "Registration did not result in non-empty registration resource")

    # FIXME: there are many more things to be tested here
