#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT
import logging
import asyncio

from aiocoap import *

logging.basicConfig(level=logging.INFO)


async def main():
    protocol = await Context.create_client_context()

    import aiocoap.oscore

    # Acting as Rikard Test 2 Entity 3
    protocol.client_credentials["coap://localhost/*"] = (
        aiocoap.oscore.SimpleGroupContext(
            algorithm=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
            hashfun=aiocoap.oscore.hashfunctions[aiocoap.oscore.DEFAULT_HASHFUNCTION],
            alg_signature=aiocoap.oscore.Ed25519(),
            alg_group_enc=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
            alg_pairwise_key_agreement=aiocoap.oscore.EcdhSsHkdf256(),
            group_id=bytes.fromhex("DD11"),
            master_secret=bytes.fromhex("11223344556677889900AABBCCDDEEFF"),
            master_salt=bytes.fromhex("1F2E3D4C5B6A7081"),
            # these are really moot given we only access this as a deterministic client
            sender_id=bytes.fromhex("52"),
            private_key=bytes.fromhex(
                "E550CD532B881D52AD75CE7B91171063E568F2531FBDFB32EE01D1910BCF810F"
            ),
            peers={
                bytes.fromhex("0A"): bytes.fromhex(
                    "CE616F28426EF24EDB51DBCEF7A23305F886F657959D4DF889DDFC0255042159"
                ),
                bytes.fromhex("51"): bytes.fromhex(
                    "2668BA6CA302F14E952228DA1250A890C143FDBA4DAED27246188B9E42C94B6D"
                ),
                # that's a new one for deterministic, and we build a key for it but no shared secret
                bytes.fromhex("dc"): None,
            },
            # requests in group mode would be sent with
            #                    ).pairwise_for(bytes.fromhex('0A'))
            # but here we want to request deterministically
        ).for_sending_deterministic_requests(bytes.fromhex("dc"), bytes.fromhex("0a"))
    )

    request = Message(code=GET, uri="coap://localhost/.well-known/core")
    response = await protocol.request(request).response
    print("Got response", response, response.payload)

    request = Message(code=GET, uri="coap://localhost/.well-known/core")
    response = await protocol.request(request).response
    print("Got response", response, response.payload)


if __name__ == "__main__":
    asyncio.run(main())
