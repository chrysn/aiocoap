# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

from .server import WithAsyncLoop, Destructing, WithClient, WithTestServer, CLEANUPTIME
import aiocoap.proxy.client
import aiocoap.cli.proxy

class WithReverseProxy(WithAsyncLoop, Destructing):
    def setUp(self):
        super(WithReverseProxy, self).setUp()

        self.servertask = asyncio.Task(aiocoap.cli.proxy.main(["--reverse", "--server-port", str(self.proxyport), "--namebased", "%s:%s"%(self.name_for_real_server, self.servernetloc)]))

    def tearDown(self):
        super(WithReverseProxy, self).tearDown()
        self.servertask.cancel()
        # TODO: find a way to use Destructing with asyncio.Task -- we should be
        # sure that when this is torn down, the proxy server is gone. without
        # proper cleanup, different test proxies could interfere.
        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))

    proxyport = 56839
    proxyaddress = 'localhost:%d'%proxyport

    name_for_real_server = 'aliasedname'

class TestReverseProxy(WithReverseProxy, WithClient, WithTestServer):
    def test_routing(self):
        yieldfrom = lambda f: self.loop.run_until_complete(f)

        request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.proxyaddress

        request.opt.uri_path = ('big',)

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.NOT_FOUND, "GET without hostname gave resource (NOT_FOUND expected)")

        request.token = None
        request.mid = None
        request.opt.uri_host = self.name_for_real_server

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.CONTENT, "GET with hostname was not successful)")

    def test_options(self):
        yieldfrom = lambda f: self.loop.run_until_complete(f)
        def req():
            request = aiocoap.Message(code=aiocoap.GET)
            request.unresolved_remote = self.proxyaddress
            request.opt.uri_path = ('big',)
            request.opt.uri_host = self.name_for_real_server
            return request
        request = req()

        request.opt.proxy_scheme = 'coap'

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.PROXYING_NOT_SUPPORTED, "Reverse proxy supports proxying even though it shouldn't.")


        request = req()
        request.opt.add_option(aiocoap.optiontypes.StringOption(2**10 + 2, "can't proxy this"))

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.BAD_OPTION, "Proxy did not react to unsafe option.")


        request = req()
        request.opt.add_option(aiocoap.optiontypes.StringOption(2**10, "nothing to see here"))

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.CONTENT, "Proxy did not ignore to safe-to-forward option.")
