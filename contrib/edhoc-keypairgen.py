#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Tool to generate credential key pairs usable with the EDHOC client and server implementation"""

import argparse
import copy
import sys

import aiocoap.edhoc
import cbor2 as cbor
import cose.keys, cose.exceptions
from edhoc.definitions import CipherSuite
import ruamel.yaml as yaml

y = yaml.YAML()

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--kid", help="ASCII key ID", default="ID")
p.add_argument('--curve', help="Curve to use (determines cipher suites, with some of them, whether the key is for signing or static key derivation)", default="X25519")
args = p.parse_args()

try:
    args.curve = cose.keys.curves.CoseCurve.from_id(args.curve)
except cose.exceptions.CoseException:
    p.error("Unknown curve; known are " + ", ".join(
        sorted(set(c.fullname for c in cose.keys.curves.CoseCurve.get_registered_classes().values()),)))

suites = CipherSuite.get_registered_ciphersuites().values()
# Would it make sense to move this decision to runtime?
# FIXME ordering?
suites = list(set(s for s in suites if s.sign_curve == args.curve or s.dh_curve == args.curve))

kty_id = args.curve.key_type
if kty_id == cose.keys.keytype.KtyOKP:
    kty_cls = cose.keys.OKPKey
    private_attrs = {cose.keys.keyparam.OKPKpD}
if kty_id == cose.keys.keytype.KtyEC2:
    kty_cls = cose.keys.EC2Key
    private_attrs = {cose.keys.keyparam.EC2KpD}
else:
    raise NotImplementedError

priv = kty_cls.generate_key(crv=args.curve)
# FIXME This would better be done with https://github.com/TimothyClaeys/pycose/issues/63 resolved
pub = copy.deepcopy(priv)
# FIXME this only applies to OKPKey and EC
for p in private_attrs:
    del pub.store[p]

id_cred = {4: args.kid.encode('ascii')}
cred = cbor.loads(pub.encode())
cred['subject name'] = ''

full_private_key = aiocoap.edhoc.EdhocPrivateKey(
        suites=suites,
        id_cred_x=id_cred,
        cred_x=cred,
        private_key=priv)

full_public_key = aiocoap.edhoc.EdhocPublicKey(
        suites=suites,
        id_cred_x=id_cred,
        cred_x=cred,
        public_key=pub)

def block_then_flow(o):
    """Prepare a YAML-serializable dict such that its items are serialized in a
    single line, but the top-level stays in the default block shape. (This
    incurs a round-trip through YAML for simplicity of implementation)."""
    itemized = y.load(yaml.dump(o))
    for item in next(iter(itemized.values())).values():
        item.fa.set_flow_style()
    return itemized

print("Put this in your own .credentials file\n")

y.dump({':own-internal-id': block_then_flow(full_private_key.to_item())}, sys.stdout)

print("\nand hand this out to everyone who wants to establish an EDHOC connection with you:\n")

y.dump({':the-peer': block_then_flow(full_public_key.to_item())}, sys.stdout)
