#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT
import logging
import asyncio

from aiocoap import *

import cbor2

logging.basicConfig(level=logging.INFO)


async def main():
    protocol = await Context.create_client_context()

    import aiocoap.oscore

    protocol.client_credentials["coap://*"] = aiocoap.oscore.SimpleGroupContext(
        alg_aead=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
        hashfun=aiocoap.oscore.hashfunctions[aiocoap.oscore.DEFAULT_HASHFUNCTION],
        alg_signature=aiocoap.oscore.Ed25519(),
        alg_group_enc=aiocoap.oscore.algorithms[aiocoap.oscore.DEFAULT_ALGORITHM],
        alg_pairwise_key_agreement=aiocoap.oscore.EcdhSsHkdf256(),
        group_id=bytes.fromhex("dd11"),
        master_secret=bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
        master_salt=bytes.fromhex("9e7ca92223786340"),
        # These are really moot given we only access this as a deterministic
        # client, but SimpleGroupContext doesn't yet understand that it could
        # be a Silent Server (which is the closest thing to a
        # deterministic-only client in the group spec)…
        sender_id=bytes.fromhex("f000"),
        private_key=bytes.fromhex(
            "E550CD532B881D52AD75CE7B91171063E568F2531FBDFB32EE01D1910BCF810F"
        ),
        sender_auth_cred=cbor2.dumps(
            {
                8: {
                    1: {
                        1: 1,
                        3: -8,
                        -1: 6,
                        -2: bytes.fromhex(
                            "5394E43633CDAC96F05120EA9F21307C9355A1B66B60A834B53E9BF60B1FB7DF"
                        ),
                    }
                }
            },
            canonical=True,
        ),
        # … but we do need those:
        peers={
            bytes.fromhex("dc"): aiocoap.oscore.DETERMINISTIC_KEY,
            bytes.fromhex("52"): bytes.fromhex("""
                    a501781a636f6170733a2f2f7365727665722e6578616d706c652e636f6d
                    026673656e64657203781a636f6170733a2f2f636c69656e742e6578616d
                    706c652e6f7267041a70004b4f08a101a401010327200621582077ec358c
                    1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b"""),
        },
        group_manager_cred=bytes.fromhex("""
                a501781a636f6170733a2f2f6d79736974652e6578616d706c652e636f6d
                026c67726f75706d616e6167657203781a636f6170733a2f2f646f6d6169
                6e2e6578616d706c652e6f7267041aab9b154f08a101a401010327200621
                5820cde3efd3bc3f99c9c9ee210415c6cba55061b5046e963b8a58c9143a
                61166472"""),
    ).for_sending_deterministic_requests(bytes.fromhex("dc"), bytes.fromhex("52"))

    request = Message(code=GET, uri="coap://localhost/helloWorld")
    response = await protocol.request(request).response
    print("Got response", response, response.payload)

    request = Message(code=GET, uri="coap://localhost/helloWorld")
    response = await protocol.request(request).response
    print("Got response", response, response.payload)


if __name__ == "__main__":
    asyncio.run(main())
