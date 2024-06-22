# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Integration tests for EDHOC"""

import unittest
import tempfile
from pathlib import Path

import aiocoap

from . import common
from .test_server import TestServer, WithClient, WithTestServer

class WithEdhocPair(WithTestServer, WithClient):
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
        client_entry = {"edhoc-oscore": {
                "suite": 2,
                "method": 3,
                "own_cred_style": "by-key-id",
                "own_cred": clientccs,
                "private_key_file": str(clientkey_file),
                "peer_cred": serverccs,
            }}
        self.client.client_credentials.load_from_dict({'coap://%s/*' % self.servernamealias: client_entry})
        self.client.client_credentials.load_from_dict({'coap://%s/*' % self.servernetloc: client_entry})

        self.server.server_credentials.load_from_dict({
            'coap://%s/*' % self.servernetloc: {"edhoc-oscore": {
                "suite": 2,
                "method": 3,
                "own_cred_style": "by-key-id",
                "own_cred": serverccs,
                "private_key_file": str(serverkey_file),
                }},
            ':client': {"edhoc-oscore": {
                "suite": 2,
                "method": 3,
                "peer_cred": clientccs,
                }},
            })

        self.server.serversite = aiocoap.oscore_sitewrapper.OscoreSiteWrapper(self.server.serversite, self.server.server_credentials)

    def tearDown(self):
        super().tearDown()
        self.tmpdir.cleanup()


edhoc_modules = aiocoap.defaults.oscore_missing_modules()
@unittest.skipIf(edhoc_modules, "EDHOC/OSCORE missing modules (%s)" % (edhoc_modules,))
class TestServerEdhoc(TestServer, WithEdhocPair):
    # FIXME: There is really no point in running all tests
    # FIXME: Verify we are actually running EDHOC
    pass

del TestServer
