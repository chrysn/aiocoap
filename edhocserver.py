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

import aiocoap.resource as resource
from aiocoap import oscore_sitewrapper
import aiocoap
import aiocoap.edhoc

from edhoc.definitions import CipherSuite0, CipherSuite1
from cose.keys import OKPKey
from cose import algorithms, curves, headers
import cbor2

# logging setup

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

def main():
    # Resource tree creation
    root = resource.Site()

    server_credentials = aiocoap.credentials.CredentialsMap()

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

#         # direct override for marco to get the test vector keys in
#
#         cred_id = {4: b'\x07'}
#         # from running once with OKPKey.generate_key(algorithm=algorithms.EdDSA,
#         # key_ops=keyops.DeriveKeyOp)
#         private_key = bytes.fromhex('bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0')
#         # to be shared with client
#         public_key = bytes.fromhex("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32")
#         cose_private_key = OKPKey(
#             crv=curves.X25519,
#             alg=algorithms.EdDSA,
#             d=private_key,
#             x=public_key,
#             )
#         return cred_id, {1: 1, -1: 4, -2: public_key, "subject name": ""}, cose_private_key, [0]

    clientrpk_key = {1: 1, -1: 4, -2: b'\x8dP\x88\xba\x0fL\xc6\xd6\npVP\xfb\xd3)x\xdc\xc0<\xd1\xe4~\x96\n\xb0\x90\x8f\xa1\xb8;6\x0e', "subject name": ""}
    server_credentials[":clientRPK"] = aiocoap.edhoc.EdhocPublicKey(
            suites=[CipherSuite0],
            id_cred_x={4: b"clientRPK"},
            cred_x=clientrpk_key,
            public_key=OKPKey.from_dict(clientrpk_key),
            )
    # not *actually* accessed until the msg3 verification accessed
    server_credentials[":clientCertificate"] = aiocoap.edhoc.EdhocPublicKey(
            suites=[CipherSuite0],
            id_cred_x={34: [-15, b'p]XE\xf3o\xc6\xa6']},
            cred_x="never used anyway",
            public_key=OKPKey(
                    crv=curves.Ed25519,
                    x=bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
                ),
            )
    marco_rpk = {1: 1, -1: 4, -2: bytes.fromhex('2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71'), "subject name": ""}
    server_credentials[":marco"] = aiocoap.edhoc.EdhocPublicKey(
            suites=[CipherSuite0],
            id_cred_x={4: b'$'},
            cred_x=marco_rpk,
            public_key=OKPKey.from_dict(marco_rpk),
            )

    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['.well-known', 'edhoc'],
            aiocoap.edhoc.EdhocResource(server_credentials))

    root = oscore_sitewrapper.OscoreSiteWrapper(root, server_credentials)

    protocol = asyncio.get_event_loop().run_until_complete(aiocoap.Context.create_server_context(root))

    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()
