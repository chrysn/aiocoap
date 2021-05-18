#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This is a temporary demo client for establishing EDHOC exchanges."""




import argparse
import asyncio
import logging
from binascii import unhexlify

import cbor2
from aiocoap import Context, Message
from aiocoap.numbers.codes import Code

from edhoc.definitions import CipherSuite0, CipherSuite1, CipherSuite2, Method, Correlation
from cose.keys import OKPKey, EC2Key, curves
from cose import algorithms, headers
from edhoc.roles.initiator import Initiator

logging.basicConfig(level=logging.INFO)


# private signature key
private_key = OKPKey(
    crv=curves.Ed25519,
    d=unhexlify("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7")
)
# copied from a later pycose documentation because that's one where we have both a d and a matching x (whereas generating keys only works for X25519 keys)
private_key = OKPKey(
        crv=curves.Ed25519,
        d=bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        x=bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
)

cert = "never used anyway"

cred_id = {headers.X5t.identifier: [algorithms.Sha256Trunc64.identifier, bytes.fromhex('705D5845F36FC6A6')]}

cred_id_for_static = {4: b'clientRPK'}

own_key_for_static = OKPKey(
    crv=curves.X25519,
    d=b'\xc8\xc5&\xb5\x151\xce\xf0v\xac\x8dac\xddI\xe4\xfb\xc8+\x07\xf7\xa9\x9f\xcf\xc6\x96\x95\x8a1p*V',
    x=b'\x8dP\x88\xba\x0fL\xc6\xd6\npVP\xfb\xd3)x\xdc\xc0<\xd1\xe4~\x96\n\xb0\x90\x8f\xa1\xb8;6\x0e',
    )

own_key_s2 = EC2Key(
        crv=curves.P256,
        d=b'\xf2\xbc\xac\x86J\x16<\x94\x03\xa3-\x07\x11:p;\x00\xc7\xe6P\xa1\x9a\x10\xcf\x1c\x10\xef\xb4:-Ga',
        x=b'\n\x0f\x96$\xe5\xef\xa9%\x9b\xc00}\xefq0\xf3\x8eB\x84q\xc1eJ\xc5\xb7x\xd6Sk\xbd\x11b',
        y=b'\xc5Z\xca$`\xe8" Skp\x94\xdf\x16\x90\xc1\\\xf8\xf3\x9e\x8a\xba\x1c\x0e<\x85\xe8\x8d.\xaa\x97H'
        )

import cose
# used as a pseudo-map so we can just have dicts and lists in there
credentials_storage = [
        ({34: [-15, b'hD\x07\x8aS\xf3\x12\xf5']}, (
            b"we don't *really* use this",
            # copied from server
            OKPKey(
                crv=curves.Ed25519,
                # from vectors
                x=bytes.fromhex("db d9 dc 8c d0 3f b7 c3 91 35 11 46 2b b2 38 16 47 7c 6b d8 d6 6e f5 a1 a0 70 ac 85 4e d7 3f d2")
            )
            )),
        # value copied from server
        ({4: b'serverRPK'}, (
                {1: 1, -1: 4, -2: b'J&\xddi\xe9\x93\xbe\xc5\x9a\xb7\xbfG)\t\x1f\x1e%\x16\xb9\xac\xed\xfe\x9d\xccX\x8c\xa1\xaf\x82PlT', "subject name": ""},
                OKPKey(
                    crv=curves.X25519,
                    x=b'J&\xddi\xe9\x93\xbe\xc5\x9a\xb7\xbfG)\t\x1f\x1e%\x16\xb9\xac\xed\xfe\x9d\xccX\x8c\xa1\xaf\x82PlT'
                    ),
                ),
            ),
        # Timothy
        ({4: b'#'}, OKPKey(
            crv=curves.X25519,
            x=bytes.fromhex('2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71')),
            ),

        ({4: b'p256key'}, (
            {1: 1, -1: 4, -2: b'\xfa\x8e)\xde\x131\xac\xfa\xae\x94^\xad\x04\xa4\xcb5SiS\xd8\xe9Z5\x07\x8d\xb1\x86!H\x1ena', -3: b":\x8faO\xda'\x8d\x9e\xa8\xbe\xc6c\xc1W\x8f\x87\xa2\xabr>\xeb\xe2X\x1f\xdf/R\x99\xdc\x0c\xba>", 'subject name': ''},
            EC2Key(
                crv=CipherSuite2.dh_curve,
                x=b'\xfa\x8e)\xde\x131\xac\xfa\xae\x94^\xad\x04\xa4\xcb5SiS\xd8\xe9Z5\x07\x8d\xb1\x86!H\x1ena',
                y=b":\x8faO\xda'\x8d\x9e\xa8\xbe\xc6c\xc1W\x8f\x87\xa2\xabr>\xeb\xe2X\x1f\xdf/R\x99\xdc\x0c\xba>",
                )
            )),
        # What Marco's responder sends
        # Some always commented out because my get_peer_cred doesn't use information that could be used to disambiguate these
#         ({4: b'\x07'}, (
#             {1: 1, -1: 6, -2: bytes.fromhex("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2"), "subject name": ""},
#             OKPKey(
#                 crv=curves.Ed25519,
#                 x=bytes.fromhex("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2")
#             )
#             )),
#         ({4: b'\x07'}, (
#             # This is direcly-as-Montgomery mode, not Edwards-after-conversion mode
#             {1: 1, -1: 4, -2: bytes.fromhex("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32"), "subject name": ""},
#             OKPKey(
#                 crv=curves.X25519,
#                 x=bytes.fromhex("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32")
#             )
#             )),
        ({4: b'\x07'}, (
            {1: 2, -1: 1, -2: bytes.fromhex('6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f'), -3: bytes.fromhex('C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800'), "subject name": ""},
            EC2Key(
                crv=curves.P256,
                x=bytes.fromhex("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f"),
                y=bytes.fromhex("C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800")
            )
            )),
    ]


async def main():
    parser = argparse.ArgumentParser()

    # 51.75.194.248
    parser.add_argument("ip", help="IP address of EDHOC responder", type=str)
    parser.add_argument("--static-static",
            help="Use static-static authentication",
            action="store_const",
            dest="method",
            const=Method.STATIC_STATIC,
            default=Method.SIGN_SIGN,
            )
    parser.add_argument("--sign-static",
            action="store_const",
            dest="method",
            const=Method.SIGN_STATIC,
            )
    parser.add_argument("--static-sign",
            action="store_const",
            dest="method",
            const=Method.STATIC_SIGN,
            )
    parser.add_argument('--suite',
            default="01",
            )

    args = parser.parse_args()

    context = await Context.create_client_context()

    suite = CipherSuite0
    supported = [suite]

    if args.method == Method.STATIC_STATIC or args.method == Method.STATIC_SIGN:
        initiator_args = dict(
            cred_idi=cred_id_for_static,
            auth_key=own_key_for_static,
            cred=({1: 1, -1: 4, -2: own_key_for_static.x, "subject name": ""}, None),
            )
    else: # sign-sign or sign-static
        initiator_args = dict(
            cred_idi=cred_id,
            auth_key=private_key,
            cred=(cert, None),
            )

    if args.suite == "01":
        pass
    elif args.suite == "2":
        suite = CipherSuite2
        supported = [suite]
        initiator_args = dict(
                # It'd be tempting to reuse the clientRPK name here, but the
                # responder callback doesn't tell the selector yet which suite
                # was picked, so they can't be disambiguated there.
                cred_idi={4: b'clientRPK'},
                auth_key=own_key_s2,
                cred=({1: 2, -1: 1, -2: own_key_s2.x, -3: own_key_s2.y, "subject name": ""}, None),
                )
    else:
        parser.error("Currently, only suite 2 is selectable")

    # the responder keys Marco expects
# #     suite = CipherSuite0
# #     supported = [CipherSuite0]
# # #     own_key_for_marco_ed = OKPKey(
# # #             crv=curves.Ed25519,
# # #             d=bytes.fromhex('2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7'),
# # #             x=bytes.fromhex('38e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149'),
# # #             )
# # #     initiator_args = dict(
# # #             cred_idi={4: b'\x24'},
# # #             auth_key=own_key_for_marco_ed,
# # #             cred=({1: 1, -1: 6, -2: own_key_for_marco_ed.x, "subject name": ""}, None),
# # #             )
# #     own_key_for_marco_x25519 = OKPKey(
# #             crv=curves.X25519,
# #             d=bytes.fromhex('2bbea655c23371c329cfbd3b1f02c6c062033837b8b59099a4436f666081b08e'),
# #             x=bytes.fromhex('2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71'),
# #             )
# #     initiator_args = dict(
# #             cred_idi={4: b'\x24'},
# #             auth_key=own_key_for_marco_x25519,
# #             cred=({1: 1, -1: 4, -2: own_key_for_marco_x25519.x, "subject name": ""}, None),
# #             )
#     suite = CipherSuite2
#     supported = [CipherSuite2]
#     own_key_for_marco_p2565 = EC2Key(
#             crv=curves.X25519,
#             d=bytes.fromhex('04f347f2bead699adb247344f347f2bdac93c7f2bead6a9d2a9b24754a1e2b62'),
#             x=bytes.fromhex('cd4177ba62433375ede279b5e18e8b91bc3ed8f1e174474a26fc0edb44ea5373'),
#             y=bytes.fromhex('A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD'),
#             )
#     initiator_args = dict(
#             cred_idi={4: b'\x24'},
#             auth_key=own_key_for_marco_p2565,
#             cred=({1: 2, -1: 1, -2: own_key_for_marco_p2565.x, -3: own_key_for_marco_p2565.y, "subject name": ""}, None),
#             )

    init = Initiator(
        method=args.method,
        corr=Correlation.CORR_1,
        conn_idi=unhexlify(b''),
        remote_cred_cb=get_peer_cred,
        supported_ciphers=supported,
        selected_cipher=suite,
        **initiator_args
        )

    msg_1 = init.create_message_one()
    # assert msg_1 == unhexlify(b"01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40")

    request = Message(code=Code.POST, payload=msg_1, uri=f"coap://{args.ip}/.well-known/edhoc")

    logging.info("POST (%s)  %s", init.edhoc_state, request.payload)
    response = await context.request(request).response

    logging.info("CHANGED (%s)  %s", init.edhoc_state, response.payload)
    msg_3 = init.create_message_three(response.payload)
    # assert msg_3 == unhexlify(_msg_3)

    logging.info("POST (%s)  %s", init.edhoc_state, request.payload)
    request = Message(code=Code.POST, payload=msg_3, uri=f"coap://{args.ip}/.well-known/edhoc")
    response = await context.request(request).response

    conn_idi, conn_idr, aead, hashf = init.finalize()

    logging.info('EDHOC key exchange successfully completed:')
    logging.info(f" - connection IDr: {conn_idr}")
    logging.info(f" - connection IDi: {conn_idi}")
    logging.info(f" - aead algorithm: {algorithms.CoseAlgorithm.from_id(aead)}")
    logging.info(f" - hash algorithm: {algorithms.CoseAlgorithm.from_id(hashf)}")

    logging.info(f" - OSCORE secret : {init.exporter('OSCORE Master Secret', 16).hex()}")
    logging.info(f" - OSCORE salt   : {init.exporter('OSCORE Master Salt', 8).hex()}")

    await context.shutdown()

def get_peer_cred(cred_id):
    for (k, v) in credentials_storage:
        if k == cred_id:
            return v
    raise RuntimeError("Can't handle unknown servers yet")


if __name__ == "__main__":
    asyncio.run(main())
