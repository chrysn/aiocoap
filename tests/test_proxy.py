# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import asyncio
import unittest

from . import common
from .test_server import WithAsyncLoop, Destructing, WithClient, TestServer, CLEANUPTIME
from .test_client import TestClientWithSetHost
import aiocoap.proxy.client
import aiocoap.cli.proxy
from aiocoap.util import hostportjoin


class WithProxyServer(WithAsyncLoop, Destructing):
    def setUp(self):
        super(WithProxyServer, self).setUp()

        self.forwardproxy = aiocoap.cli.proxy.Main(
            ["--forward", "--bind", hostportjoin(self.proxyhost, self.proxyport)]
        )
        self.loop.run_until_complete(self.forwardproxy.initializing)

    def tearDown(self):
        super(WithProxyServer, self).tearDown()
        self.loop.run_until_complete(self.forwardproxy.shutdown())

        self._del_to_be_sure("forwardproxy")

        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))

    proxyport = 56839
    proxyhost = common.loopbackname_v6 or common.loopbackname_v46
    proxyaddress = "%s:%d" % (proxyhost, proxyport)


class WithProxyClient(WithClient, WithProxyServer):
    def setUp(self):
        super(WithProxyClient, self).setUp()
        original_client_log = self.client.log
        self.client = aiocoap.proxy.client.ProxyForwarder(
            self.proxyaddress, self.client
        )
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
        request.opt.proxy_scheme = "coap"
        request.opt.uri_host = self.serveraddress
        return request

    test_replacing_resource = unittest.skipIf(
        common.using_simple6,
        "Some proxy tests fail with simple6 (https://github.com/chrysn/aiocoap/issues/88)",
    )(TestServer.test_replacing_resource)
    test_slowbig_resource = unittest.skipIf(
        common.using_simple6,
        "Some proxy tests fail with simple6 (https://github.com/chrysn/aiocoap/issues/88)",
    )(TestServer.test_slowbig_resource)


# leaving that out for a moment because it fails more slowly

# class TestClientWithProxy(WithProxyClient, TestClientWithSetHost):
#    pass

# no need to run them again
del TestClientWithSetHost
del TestServer

# none of those tests would currently work, disabling them all. see
# https://github.com/chrysn/aiocoap/issues/106
del TestServerWithProxy
