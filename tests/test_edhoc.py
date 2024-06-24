# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Integration tests for EDHOC"""

import unittest
import tempfile
from pathlib import Path

import aiocoap

from .test_server import TestServerBase, WithClient, WithTestServer
from .fixtures import no_warnings


class WithEdhocPair(WithTestServer, WithClient):
    server_style: str
    client_style: str

    def setUp(self):
        super().setUp()

        # Unlike in DTLS, we do these as a pair because we generate both key
        # pairs and distribute them to both sides

        from aiocoap import edhoc
        import aiocoap.oscore_sitewrapper

        self.tmpdir = tempfile.TemporaryDirectory()
        tmpbase = Path(self.tmpdir.name)

        serverkey_file = tmpbase / "server.cosekey"
        serverkey = edhoc.CoseKeyForEdhoc.generate(serverkey_file)
        serverccs = serverkey.as_ccs(kid=bytes.fromhex("00"), subject="s")

        clientkey_file = tmpbase / "client.cosekey"
        clientkey = edhoc.CoseKeyForEdhoc.generate(clientkey_file)
        clientccs = clientkey.as_ccs(kid=bytes.fromhex("01"), subject="c")

        # FIXME shouldn't that only need the servernamealias?
        client_entry = {
            "edhoc-oscore": {
                "suite": 2,
                "method": 3,
                "own_cred_style": self.client_style,
                "own_cred": clientccs,
                "private_key_file": str(clientkey_file),
                "peer_cred": serverccs,
            }
        }
        self.client.client_credentials.load_from_dict(
            {"coap://%s/*" % self.servernamealias: client_entry}
        )
        self.client.client_credentials.load_from_dict(
            {"coap://%s/*" % self.servernetloc: client_entry}
        )

        self.server.server_credentials.load_from_dict(
            {
                "coap://%s/*" % self.servernetloc: {
                    "edhoc-oscore": {
                        "suite": 2,
                        "method": 3,
                        "own_cred_style": self.server_style,
                        "own_cred": serverccs,
                        "private_key_file": str(serverkey_file),
                    }
                },
                ":edhocclient": {
                    "edhoc-oscore": {
                        "suite": 2,
                        "method": 3,
                        "peer_cred": clientccs,
                    }
                },
            }
        )

        self.server.serversite = aiocoap.oscore_sitewrapper.OscoreSiteWrapper(
            self.server.serversite, self.server.server_credentials
        )

    def tearDown(self):
        super().tearDown()
        self.tmpdir.cleanup()


edhoc_modules = aiocoap.defaults.oscore_missing_modules()


@unittest.skipIf(edhoc_modules, "EDHOC/OSCORE missing modules (%s)" % (edhoc_modules,))
class BaseServerEdhoc(TestServerBase, WithEdhocPair):
    @no_warnings
    def test_whoami_is_client(self):
        request = self.build_request()
        request.opt.uri_path = ["whoami"]
        response = self.fetch_response(request)
        self.assertTrue(
            b":edhocclient" in response.payload,
            f"Expected to see own role in response, got {response.payload=}",
        )


class TestServerEdhocKidKid(BaseServerEdhoc):
    server_style = "by-key-id"
    client_style = "by-key-id"


class TestServerEdhocValueValue(BaseServerEdhoc):
    server_style = "by-value"
    client_style = "by-value"


class TestServerEdhocKidValue(BaseServerEdhoc):
    server_style = "by-key-id"
    client_style = "by-value"


# that's not supposed to be tested, its child classes are
del BaseServerEdhoc
