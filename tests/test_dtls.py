# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import unittest

import aiocoap

from . import common
from .test_server import TestServer, WithClient, WithTestServer

PSK = "the PSK key"
identity = "test-client"

class WithDTLSClient(WithClient):
    def setUp(self):
        super().setUp()
        # FIXME shouldn't that only need the servernamealias?
        self.client.client_credentials.load_from_dict({'coaps://%s/*' % self.servernamealias: {"dtls": {"psk": {"ascii": PSK}, "client-identity": {"ascii": identity}}}})
        self.client.client_credentials.load_from_dict({'coaps://%s/*' % self.servernetloc: {"dtls": {"psk": {"ascii": PSK}, "client-identity": {"ascii": identity}}}})

class WithDTLSServer(WithTestServer):
    def setUp(self):
        super().setUp()
        self.server.server_credentials.load_from_dict({':client': {"dtls": {"psk": {"ascii": PSK}, "client-identity": {"ascii": identity}}}})

dtls_modules = aiocoap.defaults.dtls_missing_modules()
@unittest.skipIf(dtls_modules or common.dtls_disabled, "DTLS missing modules (%s) or disabled in this environment" % (dtls_modules,))
class TestServerDTLS(TestServer, WithDTLSClient, WithDTLSServer):
    # as with TestServerTCP

    def build_request(self):
        request = super().build_request()
        # odd default port
        request.requested_scheme = 'coaps'
        return request

del TestServer
