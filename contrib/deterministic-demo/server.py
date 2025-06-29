#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import logging
from aiocoap import oscore_sitewrapper
import aiocoap.resource as resource
import aiocoap
import asyncio

import cbor2

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)


# The resource from the upcoming draft-amsuess-core-cachable-oscore-11
class HelloWorld(resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(payload=b". ID: 42", content_format=0)


async def main():
    root = resource.Site()
    root.add_resource(
        [".well-known", "core"], resource.WKCResource(root.get_resources_as_linkheader)
    )
    root.add_resource(["helloWorld"], HelloWorld())

    server_credentials = aiocoap.credentials.CredentialsMap()

    root = oscore_sitewrapper.OscoreSiteWrapper(root, server_credentials)

    protocol = await aiocoap.Context.create_server_context(root)

    server_credentials[":a"] = aiocoap.oscore.SimpleGroupContext(
        alg_aead=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
        hashfun=aiocoap.oscore.hashfunctions[aiocoap.oscore.DEFAULT_HASHFUNCTION],
        alg_signature=aiocoap.oscore.Ed25519(),
        alg_group_enc=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
        alg_pairwise_key_agreement=aiocoap.oscore.EcdhSsHkdf256(),
        group_id=bytes.fromhex("dd11"),
        master_secret=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
        master_salt=bytes.fromhex("9e7ca92223786340"),
        sender_id=bytes.fromhex("52"),
        private_key=bytes.fromhex(
            "857eb61d3f6d70a278a36740d132c099f62880ed497e27bdfd4685fa1a304f26"
        ),
        peers={
            bytes.fromhex("dc"): aiocoap.oscore.DETERMINISTIC_KEY,
        },
        sender_auth_cred=bytes.fromhex("""
                    a501781a636f6170733a2f2f7365727665722e6578616d706c652e636f6d
                    026673656e64657203781a636f6170733a2f2f636c69656e742e6578616d
                    706c652e6f7267041a70004b4f08a101a401010327200621582077ec358c
                    1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b"""),
        group_manager_cred=bytes.fromhex("""
                a501781a636f6170733a2f2f6d79736974652e6578616d706c652e636f6d
                026c67726f75706d616e6167657203781a636f6170733a2f2f646f6d6169
                6e2e6578616d706c652e6f7267041aab9b154f08a101a401010327200621
                5820cde3efd3bc3f99c9c9ee210415c6cba55061b5046e963b8a58c9143a
                61166472"""),
    )

    await asyncio.get_running_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())
