#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This is a usage example of aiocoap that demonstrates how to implement a
simple server. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import datetime
import logging
import asyncio

import yaml

import aiocoap.resource as resource
from aiocoap import oscore_sitewrapper
import aiocoap
import aiocoap.edhoc

from edhoc.definitions import CipherSuite0, CipherSuite1, CipherSuite2, CipherSuite3
from cose.keys import OKPKey, EC2Key, curves
from cose import algorithms, headers
import cbor2

# logging setup

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

def main():
    # Resource tree creation
    root = resource.Site()

    server_credentials = aiocoap.credentials.CredentialsMap()
    server_credentials.load_from_dict(yaml.safe_load(open('edhocserver.credentials')))

    # from running once with OKPKey.generate_key(algorithm=algorithms.EdDSA,
    # key_ops=keyops.DeriveKeyOp)
    static_private_key = b'p\x05\x90#\xe2:\xdd\x08\xd68\x8d\xcb\x16\xd5\r\x83\xe8\xaa\x18O<\x92@\t\xc7+\xab\xb2\x89\xb60e'
    static_public_key = b'J&\xddi\xe9\x93\xbe\xc5\x9a\xb7\xbfG)\t\x1f\x1e%\x16\xb9\xac\xed\xfe\x9d\xccX\x8c\xa1\xaf\x82PlT'
    server_credentials[":serverRPK"] = aiocoap.edhoc.EdhocPrivateKey(
            suites=[CipherSuite0, CipherSuite1],
            id_cred_x={4: b'serverRPK'},
            cred_x={1: 1, -1: 4, -2: static_public_key, "subject name": ""},
            private_key=OKPKey(
                crv=curves.X25519,
                d=static_private_key,
                #x=static_public_key,
                )
            )
    server_credentials[":demoCertificate"] = aiocoap.edhoc.EdhocPrivateKey(
            suites=[CipherSuite0, CipherSuite1],
            id_cred_x={headers.X5t.identifier: [algorithms.Sha256Trunc64.identifier, bytes.fromhex('6844078A53F312F5')]},
            cred_x=b"we don't *really* use this",
            private_key=OKPKey(
                crv=curves.Ed25519,
                d=bytes.fromhex("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94")),
            )

    p256suites = [CipherSuite2, CipherSuite3]
    # hm, can pick the curve but still have to manually decide whether it's OKPKey or EC2Key
    p256key = EC2Key(
            crv=curves.P256,
            d=b'\x12\xf6>\x83\xa5\xbf\xa2\x17\xc7\xec\x0b\xc8k\x96\xf2\xc4\x87\x81B\xc7:\x80\xbc\xfa]\xb5\x19\xce\xe9Gm|',
            x=b'\xfa\x8e)\xde\x131\xac\xfa\xae\x94^\xad\x04\xa4\xcb5SiS\xd8\xe9Z5\x07\x8d\xb1\x86!H\x1ena',
            y=b":\x8faO\xda'\x8d\x9e\xa8\xbe\xc6c\xc1W\x8f\x87\xa2\xabr>\xeb\xe2X\x1f\xdf/R\x99\xdc\x0c\xba>",
            )
    server_credentials[":p256"] = aiocoap.edhoc.EdhocPrivateKey(
            suites=p256suites,
            id_cred_x={4: b'p256key'},
            cred_x={1: 1, -1: 4, -2: p256key.x, -3: p256key.y, "subject name": ""},
            private_key=p256key,
            )

    # The server credentials Marco expects (can all be active at the same time)
#     server_credentials = aiocoap.credentials.CredentialsMap()
#     private_ed25519_for_marco = bytes.fromhex('df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94')
#     public_ed25519_for_marco = bytes.fromhex("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2")
#     server_credentials[":forMarcoStatic"] = aiocoap.edhoc.EdhocPrivateKey(
#             suites=[CipherSuite0, CipherSuite1],
#             id_cred_x={4: b'\x07'},
#             cred_x={1: 1, -1: 6, -2: public_ed25519_for_marco, "subject name": ""},
#             private_key=OKPKey(
#                 crv=curves.Ed25519,
#                 d=private_ed25519_for_marco,
#                 )
#         )
#     private_x25519_for_marco = bytes.fromhex('bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0')
#     public_x25519_for_marco = bytes.fromhex("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32")
#     server_credentials[":forMarcoSigning"] = aiocoap.edhoc.EdhocPrivateKey(
#             suites=[CipherSuite0, CipherSuite1],
#             id_cred_x={4: b'\x07'},
#             cred_x={1: 1, -1: 4, -2: public_x25519_for_marco, "subject name": ""},
#             private_key=OKPKey(
#                 crv=curves.X25519,
#                 d=private_x25519_for_marco,
#                 )
#         )
#     private_p256_for_marco = bytes.fromhex('ec93c2f8a58f123daa982688e384f54c10c50a1d2c90c00304f648e58f14354c')
#     public_p256_for_marco_x = bytes.fromhex('6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f')
#     public_p256_for_marco_y = bytes.fromhex('C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800')
#     server_credentials[":forMarcoSuite2"] = aiocoap.edhoc.EdhocPrivateKey(
#             suites=[CipherSuite2],
#             id_cred_x={4: b'\x07'},
#             cred_x={1: 2, -1: 1, -2: public_p256_for_marco_x, -3: public_p256_for_marco_y, "subject name": ""},
#             private_key=EC2Key(
#                 crv=curves.P256,
#                 d=private_p256_for_marco,
#                 x=public_p256_for_marco_x,
#                 y=public_p256_for_marco_y,
#                 )
#         )


    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['.well-known', 'edhoc'],
            aiocoap.edhoc.EdhocResource(server_credentials))

    root = oscore_sitewrapper.OscoreSiteWrapper(root, server_credentials)

    protocol = asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))

    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()
