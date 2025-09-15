# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Integration tests for EDHOC"""

import unittest
import tempfile
from pathlib import Path

import aiocoap

from .test_server import TestServerBase, WithClient, WithTestServer
from .fixtures import no_warnings, precise_warnings


class WithEdhocPair(WithTestServer, WithClient):
    server_style: str
    client_style: str

    client_knows_server = True
    server_knows_client = True

    use_combined_edhoc = True

    async def asyncSetUp(self):
        await super().asyncSetUp()

        # Unlike in DTLS, we do these as a pair because we generate both key
        # pairs and distribute them to both sides

        from aiocoap import edhoc
        import aiocoap.oscore_sitewrapper

        self.tmpdir = tempfile.TemporaryDirectory()
        tmpbase = Path(self.tmpdir.name)

        serverkey_file = tmpbase / "server.cosekey"
        serverkey = edhoc.CoseKeyForEdhoc.generate(serverkey_file)
        serverccs = serverkey.as_ccs(kid=bytes.fromhex("00"), subject="s")
        if self.client_knows_server:
            serverccs_for_client = serverccs
        else:
            serverccs_for_client = {"unauthenticated": True}

        clientkey_file = tmpbase / "client.cosekey"
        clientkey = edhoc.CoseKeyForEdhoc.generate(clientkey_file)
        clientccs = clientkey.as_ccs(kid=bytes.fromhex("01"), subject="c")
        if self.server_knows_client:
            clientccs_for_server = clientccs
        else:
            clientccs_for_server = {"unauthenticated": True}

        # FIXME shouldn't that only need the servernamealias?
        client_entry = {
            "edhoc-oscore": {
                "suite": 2,
                "method": 3,
                "use_combined_edhoc": self.use_combined_edhoc,
                "own_cred_style": self.client_style,
                "own_cred": clientccs,
                "private_key_file": str(clientkey_file),
                "peer_cred": serverccs_for_client,
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
                        "peer_cred": clientccs_for_server,
                    }
                },
            }
        )

        self.server.serversite = aiocoap.oscore_sitewrapper.OscoreSiteWrapper(
            self.server.serversite, self.server.server_credentials
        )

    async def asyncTearDown(self):
        await super().asyncTearDown()
        self.tmpdir.cleanup()


edhoc_modules = aiocoap.defaults.oscore_missing_modules()


@unittest.skipIf(edhoc_modules, "EDHOC/OSCORE missing modules (%s)" % (edhoc_modules,))
class BaseServerEdhoc(TestServerBase, WithEdhocPair):
    @no_warnings
    async def test_whoami_is_client(self):
        request = self.build_request()
        request.opt.uri_path = ["whoami"]
        response = await self.client.request(request).response
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


class TestServerEdhocAnonKid(BaseServerEdhoc):
    server_style = "by-value"
    client_style = "by-key-id"
    client_knows_server = False


class TestServerEdhocKidAnon(BaseServerEdhoc):
    server_style = "by-key-id"
    client_style = "by-value"
    server_knows_client = False


class TestServerEdhocVeryVerbose(TestServerEdhocValueValue):
    use_combined_edhoc = False


# or derived from any other BaseServerEdhoc -- it's not like we'd get far
# enough that we'd see any styles used.
class TestEadHandling(TestServerEdhocValueValue):
    """Tests to see whether EAD items pass through or are, when critical, rejected.

    On the long run, this should be using GREASE infrastructure; as a
    short-term workaround we just test where it's easy"""

    @no_warnings
    async def test_grease_ead1(self):
        import cbor2
        import lakers

        request = self.build_request()
        request.code = aiocoap.POST
        request.opt.uri_path = [".well-known", "edhoc"]

        self.client.client_credentials.clear()

        c_i = b"a"  # We don't care, won't go through
        initiator = lakers.EdhocInitiator()
        message_1 = initiator.prepare_message_1(
            c_i, [lakers.EADItem(label=160, is_critical=False)]
        )

        request.payload = cbor2.dumps(True) + message_1

        response = await self.client.request(request).response_raising

    @precise_warnings(["Aborting EDHOC: Critical EAD1 present"])
    async def test_critical_ead1(self):
        import cbor2
        import lakers

        request = self.build_request()
        request.code = aiocoap.POST
        request.opt.uri_path = [".well-known", "edhoc"]

        self.client.client_credentials.clear()

        c_i = b"b"  # We don't care, won't go through
        initiator = lakers.EdhocInitiator()
        message_1 = initiator.prepare_message_1(
            c_i, [lakers.EADItem(label=160, is_critical=True)]
        )

        request.payload = cbor2.dumps(True) + message_1

        response = await self.client.request(request).response
        # FIXME: response_raising outputs should be capturable as BadRequest, but that's not how ResponseWrappingError currently works
        self.assertEqual(response.code, aiocoap.BAD_REQUEST)


# that's not supposed to be tested, its child classes are
del BaseServerEdhoc
