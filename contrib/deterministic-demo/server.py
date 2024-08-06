#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import logging
from aiocoap import oscore_sitewrapper
import aiocoap.resource as resource
import aiocoap
import asyncio

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)


async def main():
    # Resource tree creation
    root = resource.Site()

    root.add_resource(
        [".well-known", "core"], resource.WKCResource(root.get_resources_as_linkheader)
    )

    server_credentials = aiocoap.credentials.CredentialsMap()

    root = oscore_sitewrapper.OscoreSiteWrapper(root, server_credentials)

    protocol = await aiocoap.Context.create_server_context(root)

    # Keys from IETF109 plug test: Rikard Test 2 Entity 1
    server_credentials[":a"] = aiocoap.oscore.SimpleGroupContext(
        algorithm=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
        hashfun=aiocoap.oscore.hashfunctions[aiocoap.oscore.DEFAULT_HASHFUNCTION],
        alg_signature=aiocoap.oscore.Ed25519(),
        alg_group_enc=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
        alg_pairwise_key_agreement=aiocoap.oscore.EcdhSsHkdf256(),
        group_id=bytes.fromhex("DD11"),
        master_secret=bytes.fromhex("11223344556677889900AABBCCDDEEFF"),
        master_salt=bytes.fromhex("1F2E3D4C5B6A7081"),
        sender_id=bytes.fromhex("0A"),
        private_key=bytes.fromhex(
            "397CEB5A8D21D74A9258C20C33FC45AB152B02CF479B2E3081285F77454CF347"
        ),
        peers={
            bytes.fromhex("51"): bytes.fromhex(
                "2668BA6CA302F14E952228DA1250A890C143FDBA4DAED27246188B9E42C94B6D"
            ),
            bytes.fromhex("52"): bytes.fromhex(
                "5394E43633CDAC96F05120EA9F21307C9355A1B66B60A834B53E9BF60B1FB7DF"
            ),
            bytes.fromhex("dc"): aiocoap.oscore.DETERMINISTIC_KEY,
        },
    )

    await asyncio.get_running_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())
