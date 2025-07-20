# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import unittest

import aiocoap

from . import common
from .test_server import TestServer, WithClient, WithTestServer

PSK = "the PSK key"
identity = "test-client"


class WithDTLSClient(WithClient):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        # FIXME shouldn't that only need the servernamealias?
        self.client.client_credentials.load_from_dict(
            {
                "coaps://%s/*" % self.servernamealias: {
                    "dtls": {
                        "psk": {"ascii": PSK},
                        "client-identity": {"ascii": identity},
                    }
                }
            }
        )
        self.client.client_credentials.load_from_dict(
            {
                "coaps://%s/*" % self.servernetloc: {
                    "dtls": {
                        "psk": {"ascii": PSK},
                        "client-identity": {"ascii": identity},
                    }
                }
            }
        )


class WithDTLSServer(WithTestServer):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.server.server_credentials.load_from_dict(
            {
                ":client": {
                    "dtls": {
                        "psk": {"ascii": PSK},
                        "client-identity": {"ascii": identity},
                    }
                }
            }
        )


dtls_modules = aiocoap.defaults.dtls_missing_modules()


@unittest.skipIf(
    dtls_modules or common.dtls_disabled,
    "DTLS missing modules (%s) or disabled in this environment" % (dtls_modules,),
)
class TestServerDTLS(TestServer, WithDTLSClient, WithDTLSServer):
    # as with TestServerTCP

    def build_request(self):
        request = super().build_request()
        # odd default port
        request.requested_scheme = "coaps"
        return request


del TestServer

if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_server`
    common.run_fixture_as_standalone_server(WithDTLSServer)
