# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import unittest

from .test_server import WithClient, WithTestServer, TestServer
import secrets
import aiocoap.defaults

oscore_modules = aiocoap.defaults.oscore_missing_modules()

if not oscore_modules:
    import aiocoap.oscore
    import aiocoap.oscore_sitewrapper

_skip_unless_oscore = unittest.skipIf(oscore_modules, "Modules missing for running OSCORE tests: %s" % (oscore_modules,))

class WithGroupKeys(unittest.TestCase):
    def setUp(self):
        algorithm = aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM]
        hashfun = aiocoap.oscore.hashfunctions[aiocoap.oscore.DEFAULT_HASHFUNCTION]
        alg_countersign = aiocoap.oscore.Ed25519()

        group_id = b"G"
        participants = [b"", b"\x01", b"longname"]
        private_keys = [alg_countersign.generate() for _ in participants]
        public_keys = [alg_countersign.public_from_private(k) for k in private_keys]
        master_secret = secrets.token_bytes(64)
        master_salt = b"PoCl4"

        self.groups = [aiocoap.oscore.SimpleGroupContext(
            algorithm,
            hashfun,
            alg_countersign,
            group_id,
            master_secret,
            master_salt,
            participants[i],
            private_keys[i],
            {participants[j]: public_keys[j] for j, _ in enumerate(participants) if i != j}
            )
            for i, _ in enumerate(participants)]

        super().setUp()


class WithGroupServer(WithTestServer, WithGroupKeys):
    def setUp(self):
        super().setUp()

        server_credentials = aiocoap.credentials.CredentialsMap()
        server_credentials[":a"] = self.groups[0]
        self.server.serversite = aiocoap.oscore_sitewrapper.OscoreSiteWrapper(self.server.serversite, server_credentials)

class WithGroupClient(WithClient):
    def setUp(self):
        super().setUp()

        self.client.client_credentials['coap://%s/*' % self.servernetloc] = self.groups[1]

@_skip_unless_oscore
class TestGroupOscore(TestServer, WithGroupServer, WithGroupClient):
    pass

@_skip_unless_oscore
class TestGroupOscoreWithPairwise(TestGroupOscore):
    def setUp(self):
        super().setUp()

        for (k, v) in self.client.client_credentials.items():
            self.client.client_credentials[k] = v.pairwise_for(self.groups[0].sender_id)

del TestServer
