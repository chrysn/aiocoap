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
Ed25519PublicKey}`, respectively, and are currently implemented manually or
using ge25519.

These conversions are not too critical in that they do not run on data an
attacker can send arbitrarily (in the most dynamic situation, the keys are
distributed through a KDC aka. group manager).
"""

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

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

    # This is libsodium's crypto_sign_ed25519_pk_to_curve25519 translated into
    # the Pyton module ge25519.

    from ge25519 import ge25519, ge25519_p3
    from fe25519 import fe25519

    if ge25519.has_small_order(raw) != 0:
        raise RuntimeError("Doesn' thave small order")

    # frombytes in libsodium appears to be the same as
    # frombytes_negate_vartime; as ge25519 only implements the from_bytes
    # version, we have to do the root check manually.
    A = ge25519_p3.from_bytes(raw)
    if A.root_check:
        raise RuntimeError("Root check failed")

    if not A.is_on_main_subgroup():
        raise RuntimeError("It's on the main subgroup")

    one_minus_y = fe25519.one() - A.Y
    x = A.Y + fe25519.one()
    x = x * one_minus_y.invert()

    return x25519.X25519PublicKey.from_public_bytes(bytes(x.to_bytes()))
