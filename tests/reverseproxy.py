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

        self.reverseproxy = aiocoap.cli.proxy.Main(["--reverse", "--server-port", str(self.proxyport), "--namebased", "%s:%s"%(self.name_for_real_server, self.servernetloc), "--pathbased", "%s:%s"%("/".join(self.path_for_real_server), self.servernetloc)])
        self.loop.run_until_complete(self.reverseproxy.initializing)

    def tearDown(self):
        super(WithReverseProxy, self).tearDown()
        self.loop.run_until_complete(self.reverseproxy.shutdown())

        # creating a reference loop between the cli instance and its contexts,
        # so that the cli instance's gc-ing is linked o the contexts'.
        # TODO how can we handle this more smoothly?
        self.reverseproxy.outgoing_context._cli = self.reverseproxy
        self.reverseproxy.proxy_context._cli = self.reverseproxy

        self._del_to_be_sure('reverseproxy')

        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))

    proxyport = 56839
    proxyaddress = 'localhost:%d'%proxyport

    name_for_real_server = 'aliasedname'
    path_for_real_server = ('aliased', 'name')

class TestReverseProxy(WithReverseProxy, WithClient, WithTestServer):
    def test_routing(self):
        yieldfrom = lambda f: self.loop.run_until_complete(f)

        def req():
            request = aiocoap.Message(code=aiocoap.GET)
            request.unresolved_remote = self.proxyaddress
            request.opt.uri_path = ('big',)
            return request
        request = req()

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.NOT_FOUND, "GET without hostname gave resource (NOT_FOUND expected)")

        request = req()
        request.opt.uri_host = self.name_for_real_server

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.CONTENT, "GET with hostname based proxying was not successful)")

        request = req()
        request.opt.uri_path = self.path_for_real_server + request.opt.uri_path

        response = yieldfrom(self.client.request(request).response)
        self.assertEqual(response.code, aiocoap.CONTENT, "GET with path based proxying was not successful)")

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
