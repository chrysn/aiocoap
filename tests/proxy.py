# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

from .server import WithAsyncLoop, Destructing, WithClient, TestServer, CLEANUPTIME
from .client import TestClient
import aiocoap.proxy.client
import aiocoap.cli.proxy

class WithProxyServer(WithAsyncLoop, Destructing):
    def setUp(self):
        super(WithProxyServer, self).setUp()

        self.forwardproxy = aiocoap.cli.proxy.Main(["--forward", "--server-port", str(self.proxyport)])
        self.loop.run_until_complete(self.forwardproxy.initializing)

    def tearDown(self):
        super(WithProxyServer, self).tearDown()
        self.loop.run_until_complete(self.forwardproxy.shutdown())

        # creating a reference loop between the cli instance and its contexts,
        # so that the cli instance's gc-ing is linked o the contexts'.
        # TODO how can we handle this more smoothly?
        self.forwardproxy.outgoing_context._cli = self.reverseproxy
        self.forwardproxy.proxy_context._cli = self.reverseproxy

        self._del_to_be_sure('forwardproxy')

        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))

    proxyport = 56839
    proxyaddress = 'localhost:%d'%proxyport

class WithProxyClient(WithClient, WithProxyServer):
    def setUp(self):
        super(WithProxyClient, self).setUp()
        original_client_log = self.client.log
        self.client = aiocoap.proxy.client.ProxyForwarder(self.proxyaddress, self.client)
        self.client.log = original_client_log

    def tearDown(self):
        self.client = self.client.context

class TestServerWithProxy(WithProxyClient, TestServer):
    def build_request(self):
        # this needs to be run differently because tests/server.py
        # doesn't exactly use the high-level apis. (and that's ok because we need
        # to test the server with simple messages too.)

        request = aiocoap.Message(code=aiocoap.GET)
        request.unresolved_remote = self.proxyaddress
        request.opt.proxy_scheme = 'coap'
        request.opt.uri_host = self.serveraddress
        return request

# leaving that out for a moment because it fails more slowly

#class TestClientWithProxy(WithProxyClient, TestClient):
#    pass

# no need to run them again
del TestClient
del TestServer
