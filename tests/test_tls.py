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
import unittest
import sys

import aiocoap

from .test_server import WithClient, WithTestServer, run_fixture_as_standalone_server

from .fixtures import no_warnings, asynctest
from .common import tcp_disabled

IS_STANDALONE = False

class WithTLSServer(WithTestServer):
    def setUp(self):
        self.keydir = tempfile.mkdtemp(suffix="-testkeypair")
        self.keyfile = self.keydir + '/key.pem'
        self.certfile = self.keydir + '/cert.pem'
        self.credentialsfile = self.keydir + '/credentials.json'
        subprocess.check_call([
            'openssl',
            'req',
            '-x509',
            '-newkey', 'rsa:4096',
            '-keyout', self.keyfile,
            '-out', self.certfile,
            '-days', '5',
            '-nodes', '-subj', '/CN=%s' % self.servernamealias
            ],
            stderr=subprocess.DEVNULL,
            )

        # Write out for the benefit of standalone clients during debugging
        with open(self.credentialsfile, 'w') as of:
            json.dump({
                'coaps+tcp://%s/*' % self.servernamealias: {'tlscert': { 'certfile': self.certfile }}
            }, of)

        if IS_STANDALONE:
            print("To test, run ./aiocoap-client coaps+tcp://%s/whoami --credentials %s" % (self.servernamealias, self.credentialsfile,))

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
        if hasattr(ssl_context, 'sni_callback'): # starting python 3.7
            ssl_context.sni_callback = lambda obj, name, context: setattr(obj, "indicated_server_name", name)
        return ssl_context

class WithTLSClient(WithClient):
    # This expects that something -- typically the colocated WithTestServer -- sets certfile first
    def setUp(self):
        super().setUp()

        self.client.client_credentials['coaps+tcp://%s/*' % self.servernamealias] = aiocoap.credentials.TLSCert(certfile=self.certfile)

@unittest.skipIf(tcp_disabled, "TCP disabled in environment")
class TestTLS(WithTLSServer, WithTLSClient):
    @no_warnings
    @asynctest
    async def test_tls(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri('coaps+tcp://%s/whoami' % self.servernamealias, set_uri_host=False)
        response = await self.client.request(request).response_raising

        response = json.loads(response.payload)
        self.assertEqual(response['requested_uri'], 'coaps+tcp://%s/whoami' % self.servernamealias, "SNI name was not used by the server")

    if sys.version_info < (3, 7):
        test_tls = unittest.expectedFailure(test_tls) # SNI support was only added in Python 3.7
    if 'PyPy' in sys.version:
        # For PyPy exclusion, see https://foss.heptapod.net/pypy/pypy/-/issues/3359
        # Completely skipping a test that causes segfaults
        test_tls = None

if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_server`
    IS_STANDALONE = True
    import logging
    logging.basicConfig(level=logging.DEBUG)
    run_fixture_as_standalone_server(TestTLS)
