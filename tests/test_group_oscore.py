# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import unittest

from .test_server import WithClient, WithTestServer, TestServer
import secrets
import aiocoap.defaults

oscore_modules = aiocoap.defaults.oscore_missing_modules()

if not oscore_modules:
    import aiocoap.oscore
    import aiocoap.oscore_sitewrapper
    import cbor2

_skip_unless_oscore = unittest.skipIf(
    oscore_modules, "Modules missing for running OSCORE tests: %s" % (oscore_modules,)
)


class WithGroupKeys(unittest.TestCase):
    def _set_up_algorithms(self):
        self.alg_aead = aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM]
        self.alg_group_enc = aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM]
        self.hashfun = aiocoap.oscore.hashfunctions[aiocoap.oscore.DEFAULT_HASHFUNCTION]
        self.alg_countersign = aiocoap.oscore.Ed25519()
        self.alg_pairwise_key_agreement = aiocoap.oscore.EcdhSsHkdf256()

    def setUp(self):
        self._set_up_algorithms()

        group_id = b"G"
        participants = [b"", b"\x01", b"longname"]
        private_keys, creds = zip(
            *(self.alg_countersign.generate_with_ccs() for _ in participants)
        )
        master_secret = secrets.token_bytes(64)
        master_salt = b"PoCl4"
        # This would only be processed when there is actual contact with the GM
        gm_cred = b"dummy credential"

        self.groups = [
            aiocoap.oscore.SimpleGroupContext(
                self.alg_aead,
                self.hashfun,
                self.alg_countersign,
                self.alg_group_enc,
                self.alg_pairwise_key_agreement,
                group_id,
                master_secret,
                master_salt,
                participants[i],
                private_keys[i],
                creds[i],
                {
                    participants[j]: creds[j]
                    for j, _ in enumerate(participants)
                    if i != j
                },
                gm_cred,
                group_manager_cred_fmt="dummy",
            )
            for i, _ in enumerate(participants)
        ]

        super().setUp()


class WithGroupServer(WithTestServer, WithGroupKeys):
    def setUp(self):
        super().setUp()

        server_credentials = aiocoap.credentials.CredentialsMap()
        server_credentials[":a"] = self.groups[0]
        self.server.serversite = aiocoap.oscore_sitewrapper.OscoreSiteWrapper(
            self.server.serversite, server_credentials
        )


class WithGroupClient(WithClient):
    def setUp(self):
        super().setUp()

        self.client.client_credentials["coap://%s/*" % self.servernetloc] = self.groups[
            1
        ]


@_skip_unless_oscore
class TestGroupOscore(TestServer, WithGroupServer, WithGroupClient):
    pass


@_skip_unless_oscore
class TestGroupOscoreWithPairwise(TestGroupOscore):
    def setUp(self):
        super().setUp()

        for k, v in self.client.client_credentials.items():
            self.client.client_credentials[k] = v.pairwise_for(self.groups[0].sender_id)


@_skip_unless_oscore
class TestDifferentLengths(TestGroupOscore):
    def _set_up_algorithms(self):
        super()._set_up_algorithms()
        # Override Group Encryption Algorithm to have 16 bytes nonce rather than the 13 of alg_aead
        self.alg_group_enc = aiocoap.oscore.A128CBC


# For the different length tests, it completely suffices to just run one.
for _testname in dir(TestDifferentLengths):
    if not _testname.startswith("test_"):
        continue
    if _testname != "test_big_resource":
        setattr(TestDifferentLengths, _testname, None)
assert any(
    getattr(TestDifferentLengths, _t) is not None
    for _t in dir(TestDifferentLengths)
    if _t.startswith("test_")
), "Removing tests left none"


@_skip_unless_oscore
class TestDifferentLengthsWithPairwise(
    TestDifferentLengths, TestGroupOscoreWithPairwise
):
    pass


del TestServer
