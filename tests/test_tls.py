# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import json
import tempfile
import shutil
import subprocess

import aiocoap

from .test_server import WithClient, WithTestServer, run_fixture_as_standalone_server
from .test_client import TestClientWithSetHost

from .fixtures import no_warnings, asynctest

class WithTLSServer(WithTestServer):
    def setUp(self):
        self.keydir = tempfile.mkdtemp(suffix="-testkeypair")
        self.keyfile = self.keydir + '/key.pem'
        self.certfile = self.keydir + '/cert.pem'
        subprocess.check_call([
            'openssl',
            'req',
            '-x509',
            '-newkey', 'rsa:4096',
            '-keyout', self.keyfile,
            '-out', self.certfile,
            '-days', '5',
            '-nodes', '-subj', '/CN=%s' % self.servernamealias
            ])

        super().setUp()

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.keydir)

    def get_server_ssl_context(self):
        import ssl

        # FIXME: copied from aiocoap.cli.common
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        ssl_context.set_alpn_protocols(["coap"])
        return ssl_context

class TestTLS(WithTLSServer, WithClient):
    @no_warnings
    @asynctest
    async def test_tls(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri('coaps+tcp://%s/whoami' % self.servernamealias, set_uri_host=False)
        response = await self.client.request(request).response_raising

        response = json.loads(response.payload)
        self.assertEqual(response['requested_uri'], 'coap+tls://%s/whoami' % self.servernamealias, "SNI name was not used by the server")

if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_server`
    import logging
    logging.basicConfig(level=logging.DEBUG)
    run_fixture_as_standalone_server(TestTLS)
