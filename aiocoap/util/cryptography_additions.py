# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""
Workaround for https://github.com/pyca/cryptography/issues/5557

These functions could be methods to
`cryptography.hazmat.primitives.asymmetric.ed25519.{Ed25519PrivateKey,
Ed25519PublicKey}`, respectively, and are currently implemented using NaCl.

(A more portable workaround would follow what californium is doing_, but
the better solution is for cryptography to provide it).

.. _doing: https://github.com/rikard-sics/californium/blob/group_oscore/cf-oscore/src/main/java/org/eclipse/californium/oscore/group/KeyRemapping.java#L239
"""

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

import nacl.signing

def sk_to_curve25519(ed: ed25519.Ed25519PrivateKey) -> x25519.X25519PrivateKey:
    raw = ed.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
            )

    # as proposed in https://github.com/pyca/cryptography/issues/5557#issuecomment-739339132

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends.openssl.backend import backend

    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(raw)
    h = bytearray(hasher.finalize())
    # curve25519 clamping
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64

    return backend.x25519_load_private_bytes(h[0:32])

def pk_to_curve25519(ed: ed25519.Ed25519PublicKey) -> x25519.X25519PublicKey:
    raw = ed.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
            )

    ed_nacl = nacl.signing.VerifyKey(
            key=raw,
            )

    x_nacl = ed_nacl.to_curve25519_public_key()

    return x25519.X25519PublicKey.from_public_bytes(x_nacl.encode())
