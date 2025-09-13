# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import json
import tempfile
import shutil
import subprocess
import unittest
import sys

import aiocoap

from .test_server import WithClient, WithTestServer

from .fixtures import no_warnings
from .common import tcp_disabled, run_fixture_as_standalone_server

IS_STANDALONE = False


class WithTLSServer(WithTestServer):
    async def asyncSetUp(self):
        self.keydir = tempfile.mkdtemp(suffix="-testkeypair")
        self.keyfile = self.keydir + "/key.pem"
        self.certfile = self.keydir + "/cert.pem"
        self.credentialsfile = self.keydir + "/credentials.json"
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-keyout",
                self.keyfile,
                "-out",
                self.certfile,
                "-days",
                "5",
                "-nodes",
                "-subj",
                "/CN=%s" % self.servernamealias,
            ],
            stderr=subprocess.DEVNULL,
        )

        # Write out for the benefit of standalone clients during debugging
        with open(self.credentialsfile, "w") as of:
            json.dump(
                {
                    "coaps+tcp://%s/*" % self.servernamealias: {
                        "tlscert": {"certfile": self.certfile}
                    }
                },
                of,
            )

        if IS_STANDALONE:
            print(
                "To test, run ./aiocoap-client coaps+tcp://%s/whoami --credentials %s"
                % (
                    self.servernamealias,
                    self.credentialsfile,
                )
            )

        await super().asyncSetUp()

    async def asyncTearDown(self):
        await super().asyncTearDown()
        shutil.rmtree(self.keydir)

    def get_server_ssl_context(self):
        import ssl

        # FIXME: copied from aiocoap.cli.common
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        ssl_context.set_alpn_protocols(["coap"])
        ssl_context.sni_callback = lambda obj, name, context: setattr(
            obj, "indicated_server_name", name
        )
        return ssl_context


class WithTLSClient(WithClient):
    # This expects that something -- typically the colocated WithTestServer -- sets certfile first
    async def asyncSetUp(self):
        await super().asyncSetUp()

        # we're not async ourself, but WithClient only sets up the client in
        # asyncSetUp, and apparently, setUp runs before asyncSetUp, so we have
        # to be in (and wait for) asyncSetUp too

        self.client.client_credentials["coaps+tcp://%s/*" % self.servernamealias] = (
            aiocoap.credentials.TLSCert(certfile=self.certfile)
        )


@unittest.skipIf(tcp_disabled, "TCP disabled in environment")
class TestTLS(WithTLSServer, WithTLSClient):
    @no_warnings
    async def test_tls(self):
        request = aiocoap.Message(code=aiocoap.GET)
        request.set_request_uri(
            "coaps+tcp://%s/whoami" % self.servernamealias, set_uri_host=False
        )
        response = await self.client.request(request).response_raising

        response = json.loads(response.payload)
        self.assertEqual(
            response["requested_uri"],
            "coaps+tcp://%s/whoami" % self.servernamealias,
            "SNI name was not used by the server",
        )


if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_server`
    IS_STANDALONE = True
    import logging

    logging.basicConfig(level=logging.DEBUG)
    run_fixture_as_standalone_server(TestTLS)
