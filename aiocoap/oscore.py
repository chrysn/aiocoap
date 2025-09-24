# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module contains the tools to send OSCORE secured messages.

It only deals with the algorithmic parts, the security context and protection
and unprotection of messages. It does not touch on the integration of OSCORE in
the larger aiocoap stack of having a context or requests; that's what
:mod:`aiocoap.transports.osore` is for.`"""

from __future__ import annotations

from collections import namedtuple
import io
import json
import binascii
import os
import os.path
import tempfile
import abc
from typing import Optional, List, Any, Tuple
import secrets
import warnings
import logging

from aiocoap.message import Message, Direction
from aiocoap.util import cryptography_additions, deprecation_getattr, Sentinel
from aiocoap.numbers import GET, POST, FETCH, CHANGED, UNAUTHORIZED, CONTENT
from aiocoap import error
from . import credentials
from aiocoap.defaults import log_secret

from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import ciphers, hashes
import cryptography.hazmat.backends
import cryptography.exceptions
from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

import cbor2 as cbor

import filelock

# Logger through which log events from cryptographic operations (both inside
# the primitives and around key derivation) are traced.
_alglog = logging.getLogger("aiocoap.cryptography")

MAX_SEQNO = 2**40 - 1

# Relevant values from the IANA registry "CBOR Object Signing and Encryption (COSE)"
COSE_KID = 4
COSE_PIV = 6
COSE_KID_CONTEXT = 10
# from RFC9338
COSE_COUNTERSIGNATURE0 = 12
# from RFC9528
COSE_KCCS = 14

COMPRESSION_BITS_N = 0b111
COMPRESSION_BIT_K = 0b1000
COMPRESSION_BIT_H = 0b10000
COMPRESSION_BIT_GROUP = 0b100000  # Group Flag from draft-ietf-core-oscore-groupcomm-21
COMPRESSION_BITS_RESERVED = 0b11000000

CWT_CLAIM_CNF = 8
CWT_CNF_COSE_KEY = 1
COSE_KEY_COMMON_KTY = 1
COSE_KTY_OKP = 1
COSE_KTY_EC2 = 2
COSE_KEY_COMMON_ALG = 3
COSE_KEY_OKP_CRV = -1
COSE_KEY_OKP_X = -2
COSE_KEY_EC2_X = -2
COSE_KEY_EC2_Y = -3

# While the original values were simple enough to be used in literals, starting
# with oscore-groupcomm we're using more compact values

INFO_TYPE_KEYSTREAM_REQUEST = True
INFO_TYPE_KEYSTREAM_RESPONSE = False

PRESENT_BUT_NO_VALUE_YET = Sentinel("Value will be populated later")


class CodeStyle(namedtuple("_CodeStyle", ("request", "response"))):
    FETCH_CONTENT: CodeStyle
    POST_CHANGED: CodeStyle

    @classmethod
    def from_request(cls, request) -> CodeStyle:
        if request == FETCH:
            return cls.FETCH_CONTENT
        elif request == POST:
            return cls.POST_CHANGED
        else:
            raise ValueError("Invalid request code %r" % request)


CodeStyle.FETCH_CONTENT = CodeStyle(FETCH, CONTENT)
CodeStyle.POST_CHANGED = CodeStyle(POST, CHANGED)


class _DeterministicKey:
    """Singleton to indicate that for this key member no public or private key
    is available because it is the Deterministic Client (see
    <https://www.ietf.org/archive/id/draft-amsuess-core-cachable-oscore-01.html>)

    This is highly experimental not only from an implementation but also from a
    specification point of view. The specification has not received adaequate
    review that would justify using it in any non-experimental scenario.
    """


DETERMINISTIC_KEY = _DeterministicKey()


class NotAProtectedMessage(error.Error, ValueError):
    """Raised when verification is attempted on a non-OSCORE message"""

    def __init__(self, message, plain_message):
        super().__init__(message)
        self.plain_message = plain_message


class ProtectionInvalid(error.Error, ValueError):
    """Raised when verification of an OSCORE message fails"""


class DecodeError(ProtectionInvalid):
    """Raised when verification of an OSCORE message fails because CBOR or compressed data were erroneous"""


class ReplayError(ProtectionInvalid):
    """Raised when verification of an OSCORE message fails because the sequence numbers was already used"""


class ReplayErrorWithEcho(ProtectionInvalid, error.RenderableError):
    """Raised when verification of an OSCORE message fails because the
    recipient replay window is uninitialized, but a 4.01 Echo can be
    constructed with the data in the exception that can lead to the client
    assisting in replay window recovery"""

    def __init__(self, secctx, request_id, echo):
        self.secctx = secctx
        self.request_id = request_id
        self.echo = echo

    def to_message(self):
        inner = Message(
            code=UNAUTHORIZED,
            echo=self.echo,
        )
        outer, _ = self.secctx.protect(inner, request_id=self.request_id)
        return outer


class ContextUnavailable(error.Error, ValueError):
    """Raised when a context is (currently or permanently) unavailable for
    protecting or unprotecting a message"""


class RequestIdentifiers:
    """A container for details that need to be passed along from the
    (un)protection of a request to the (un)protection of the response; these
    data ensure that the request-response binding process works by passing
    around the request's partial IV.

    Users of this module should never create or interact with instances, but
    just pass them around.
    """

    def __init__(self, kid, partial_iv, can_reuse_nonce, request_code):
        # The sender ID of whoever generated the partial IV
        self.kid = kid
        self.partial_iv = partial_iv
        self.can_reuse_nonce = can_reuse_nonce
        self.code_style = CodeStyle.from_request(request_code)

        self.request_hash = None

    def get_reusable_kid_and_piv(self):
        """Return the kid and the partial IV if can_reuse_nonce is True, and
        set can_reuse_nonce to False."""

        if self.can_reuse_nonce:
            self.can_reuse_nonce = False
            return (self.kid, self.partial_iv)
        else:
            return (None, None)


def _xor_bytes(a, b):
    assert len(a) == len(b), "XOR needs consistent lengths"
    # FIXME is this an efficient thing to do, or should we store everything
    # that possibly needs xor'ing as long integers with an associated length?
    return bytes(_a ^ _b for (_a, _b) in zip(a, b))


class SymmetricEncryptionAlgorithm(metaclass=abc.ABCMeta):
    """A symmetric algorithm

    The algorithm's API is the AEAD API with addtional authenticated data: The
    algorihm may or may not verify that data. Algorithms that actually do
    verify the data are recognized by also being AeadAlgorithm.
    """

    value: int
    key_bytes: int
    tag_bytes: int
    iv_bytes: int

    @abc.abstractmethod
    def encrypt(cls, plaintext, aad, key, iv):
        """Return ciphertext + tag for given input data"""

    @abc.abstractmethod
    def decrypt(cls, ciphertext_and_tag, aad, key, iv):
        """Reverse encryption. Must raise ProtectionInvalid on any error
        stemming from untrusted data."""

    @staticmethod
    def _build_encrypt0_structure(protected, external_aad):
        assert protected == {}, "Unexpected data in protected bucket"
        protected_serialized = b""  # were it into an empty dict, it'd be the cbor dump
        enc_structure = ["Encrypt0", protected_serialized, external_aad]

        return cbor.dumps(enc_structure)


class AeadAlgorithm(SymmetricEncryptionAlgorithm, metaclass=abc.ABCMeta):
    """A symmetric algorithm that provides authentication, including
    authentication of additional data."""


class AES_CBC(SymmetricEncryptionAlgorithm, metaclass=abc.ABCMeta):
    """AES in CBC mode using tthe Python cryptography library"""

    tag_bytes = 0
    # This introduces padding -- this library doesn't need to care because
    # Python does allocation for us, but others may need to rethink their
    # buffer allocation strategies.

    @classmethod
    def _cipher(cls, key, iv):
        return ciphers.base.Cipher(
            ciphers.algorithms.AES(key),
            ciphers.modes.CBC(iv),
        )

    @classmethod
    def encrypt(cls, plaintext, _aad, key, iv):
        # FIXME: Ignoring aad violates https://www.rfc-editor.org/rfc/rfc9459.html#name-implementation-consideratio but is required for Group OSCORE

        # Padding according to https://www.rfc-editor.org/rfc/rfc5652#section-6.3
        k = cls.key_bytes
        assert k < 256, (
            "Algorithm with this key size should not have been created in the first plae"
        )
        pad_byte = k - (len(plaintext) % k)
        pad_bytes = bytes((pad_byte,)) * pad_byte
        plaintext += pad_bytes

        encryptor = cls._cipher(key, iv).encryptor()
        result = encryptor.update(plaintext)
        result += encryptor.finalize()
        return result

    @classmethod
    def decrypt(cls, ciphertext_and_tag, _aad, key, iv):
        # FIXME: Ignoring aad violates https://www.rfc-editor.org/rfc/rfc9459.html#name-implementation-consideratio but is required for Group OSCORE

        k = cls.key_bytes
        if ciphertext_and_tag == b"" or len(ciphertext_and_tag) % k != 0:
            raise ProtectionInvalid("Message length does not match padding")

        decryptor = cls._cipher(key, iv).decryptor()
        result = decryptor.update(ciphertext_and_tag)
        result += decryptor.finalize()

        # Padding according to https://www.rfc-editor.org/rfc/rfc5652#section-6.3
        claimed_padding = result[-1]
        if claimed_padding == 0 or claimed_padding > k:
            raise ProtectionInvalid("Padding does not match key")
        if result[-claimed_padding:] != bytes((claimed_padding,)) * claimed_padding:
            raise ProtectionInvalid("Padding is inconsistent")

        return result[:-claimed_padding]


class A128CBC(AES_CBC):
    # from RFC9459
    value = -65531
    key_bytes = 16  # 128-bit key
    iv_bytes = 16  # 16-octet nonce


class AES_CCM(AeadAlgorithm, metaclass=abc.ABCMeta):
    """AES-CCM implemented using the Python cryptography library"""

    @classmethod
    def encrypt(cls, plaintext, aad, key, iv):
        return aead.AESCCM(key, cls.tag_bytes).encrypt(iv, plaintext, aad)

    @classmethod
    def decrypt(cls, ciphertext_and_tag, aad, key, iv):
        try:
            return aead.AESCCM(key, cls.tag_bytes).decrypt(iv, ciphertext_and_tag, aad)
        except cryptography.exceptions.InvalidTag:
            raise ProtectionInvalid("Tag invalid")


class AES_CCM_16_64_128(AES_CCM):
    # from RFC8152 and draft-ietf-core-object-security-0[012] 3.2.1
    value = 10
    key_bytes = 16  # 128-bit key
    tag_bytes = 8  # 64-bit tag
    iv_bytes = 13  # 13-byte nonce


class AES_CCM_16_64_256(AES_CCM):
    # from RFC8152
    value = 11
    key_bytes = 32  # 256-bit key
    tag_bytes = 8  # 64-bit tag
    iv_bytes = 13  # 13-byte nonce


class AES_CCM_64_64_128(AES_CCM):
    # from RFC8152
    value = 12
    key_bytes = 16  # 128-bit key
    tag_bytes = 8  # 64-bit tag
    iv_bytes = 7  # 7-byte nonce


class AES_CCM_64_64_256(AES_CCM):
    # from RFC8152
    value = 13
    key_bytes = 32  # 256-bit key
    tag_bytes = 8  # 64-bit tag
    iv_bytes = 7  # 7-byte nonce


class AES_CCM_16_128_128(AES_CCM):
    # from RFC8152
    value = 30
    key_bytes = 16  # 128-bit key
    tag_bytes = 16  # 128-bit tag
    iv_bytes = 13  # 13-byte nonce


class AES_CCM_16_128_256(AES_CCM):
    # from RFC8152
    value = 31
    key_bytes = 32  # 256-bit key
    tag_bytes = 16  # 128-bit tag
    iv_bytes = 13  # 13-byte nonce


class AES_CCM_64_128_128(AES_CCM):
    # from RFC8152
    value = 32
    key_bytes = 16  # 128-bit key
    tag_bytes = 16  # 128-bit tag
    iv_bytes = 7  # 7-byte nonce


class AES_CCM_64_128_256(AES_CCM):
    # from RFC8152
    value = 33
    key_bytes = 32  # 256-bit key
    tag_bytes = 16  # 128-bit tag
    iv_bytes = 7  # 7-byte nonce


class AES_GCM(AeadAlgorithm, metaclass=abc.ABCMeta):
    """AES-GCM implemented using the Python cryptography library"""

    iv_bytes = 12  # 96 bits fixed size of the nonce

    @classmethod
    def encrypt(cls, plaintext, aad, key, iv):
        return aead.AESGCM(key).encrypt(iv, plaintext, aad)

    @classmethod
    def decrypt(cls, ciphertext_and_tag, aad, key, iv):
        try:
            return aead.AESGCM(key).decrypt(iv, ciphertext_and_tag, aad)
        except cryptography.exceptions.InvalidTag:
            raise ProtectionInvalid("Tag invalid")


class A128GCM(AES_GCM):
    # from RFC8152
    value = 1
    key_bytes = 16  # 128-bit key
    tag_bytes = 16  # 128-bit tag


class A192GCM(AES_GCM):
    # from RFC8152
    value = 2
    key_bytes = 24  # 192-bit key
    tag_bytes = 16  # 128-bit tag


class A256GCM(AES_GCM):
    # from RFC8152
    value = 3
    key_bytes = 32  # 256-bit key
    tag_bytes = 16  # 128-bit tag


class ChaCha20Poly1305(AeadAlgorithm):
    # from RFC8152
    value = 24
    key_bytes = 32  # 256-bit key
    tag_bytes = 16  # 128-bit tag
    iv_bytes = 12  # 96-bit nonce

    @classmethod
    def encrypt(cls, plaintext, aad, key, iv):
        return aead.ChaCha20Poly1305(key).encrypt(iv, plaintext, aad)

    @classmethod
    def decrypt(cls, ciphertext_and_tag, aad, key, iv):
        try:
            return aead.ChaCha20Poly1305(key).decrypt(iv, ciphertext_and_tag, aad)
        except cryptography.exceptions.InvalidTag:
            raise ProtectionInvalid("Tag invalid")


class AlgorithmCountersign(metaclass=abc.ABCMeta):
    """A fully parameterized COSE countersign algorithm

    An instance is able to provide all the alg_signature, par_countersign and
    par_countersign_key parameters taht go into the Group OSCORE algorithms
    field.
    """

    value: int | str

    @abc.abstractmethod
    def sign(self, body, external_aad, private_key):
        """Return the signature produced by the key when using
        CounterSignature0 as describe in draft-ietf-cose-countersign-01"""

    @abc.abstractmethod
    def verify(self, signature, body, external_aad, public_key):
        """Verify a signature in analogy to sign"""

    @abc.abstractmethod
    def generate_with_ccs(self) -> Tuple[Any, bytes]:
        """Return a usable private key along with a CCS describing it"""

    @abc.abstractmethod
    def public_from_private(self, private_key):
        """Given a private key, derive the publishable key"""

    @abc.abstractmethod
    def from_kccs(self, ccs: bytes) -> Any:
        """Given a CCS, extract the public key, or raise a ValueError if the
        credential format does not align with the type.

        The type is not exactly Any, but whichever type is used by this
        algorithm class."""

    @staticmethod
    def _build_countersign_structure(body, external_aad):
        countersign_structure = [
            "CounterSignature0",
            b"",
            b"",
            external_aad,
            body,
        ]
        tobesigned = cbor.dumps(countersign_structure)
        return tobesigned

    @abc.abstractproperty
    def signature_length(self) -> int:
        """The length of a signature using this algorithm"""

    @abc.abstractproperty
    def curve_number(self) -> int:
        """Registered curve number used with this algorithm.

        Only used for verification of credentials' details"""


class AlgorithmStaticStatic(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def staticstatic(self, private_key, public_key):
        """Derive a shared static-static secret from a private and a public key"""


def _from_kccs_common(ccs: bytes) -> dict:
    """Check that the CCS contains a CNF claim that is a COSE Key, and return
    that key"""

    try:
        parsed = cbor.loads(ccs)
    except cbor.CBORDecodeError as e:
        raise ValueError("CCS not in CBOR format") from e

    if (
        not isinstance(parsed, dict)
        or CWT_CLAIM_CNF not in parsed
        or not isinstance(parsed[CWT_CLAIM_CNF], dict)
        or CWT_CNF_COSE_KEY not in parsed[CWT_CLAIM_CNF]
        or not isinstance(parsed[CWT_CLAIM_CNF][CWT_CNF_COSE_KEY], dict)
    ):
        raise ValueError("CCS must contain a COSE Key dict in a CNF")

    return parsed[CWT_CLAIM_CNF][CWT_CNF_COSE_KEY]


class Ed25519(AlgorithmCountersign):
    def sign(self, body, aad, private_key):
        _alglog.debug("Perfoming signature:")
        _alglog.debug("* body: %s", body.hex())
        _alglog.debug("* AAD: %s", aad.hex())
        private_key = asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
            private_key
        )
        return private_key.sign(self._build_countersign_structure(body, aad))

    def verify(self, signature, body, aad, public_key):
        _alglog.debug("Verifying signature:")
        _alglog.debug("* body: %s", body.hex())
        _alglog.debug("* AAD: %s", aad.hex())
        public_key = asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        try:
            public_key.verify(signature, self._build_countersign_structure(body, aad))
        except cryptography.exceptions.InvalidSignature:
            _alglog.debug("Signature was invalid.")
            raise ProtectionInvalid("Signature mismatch")

    def _generate(self):
        key = asymmetric.ed25519.Ed25519PrivateKey.generate()
        # FIXME: We could avoid handing the easy-to-misuse bytes around if the
        # current algorithm interfaces did not insist on passing the
        # exchangable representations -- and generally that should be more
        # efficient.
        return key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def generate_with_ccs(self) -> Tuple[Any, bytes]:
        private = self._generate()
        public = self.public_from_private(private)

        ccs = cbor.dumps(
            {
                CWT_CLAIM_CNF: {
                    CWT_CNF_COSE_KEY: {
                        COSE_KEY_COMMON_KTY: COSE_KTY_OKP,
                        COSE_KEY_COMMON_ALG: self.value,
                        COSE_KEY_OKP_CRV: self.curve_number,
                        COSE_KEY_OKP_X: public,
                    }
                }
            }
        )

        return (private, ccs)

    def public_from_private(self, private_key):
        private_key = asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
            private_key
        )
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def from_kccs(self, ccs: bytes) -> Any:
        # eg. {1: 1, 3: -8, -1: 6, -2: h'77 ... 88'}
        cose_key = _from_kccs_common(ccs)

        if (
            cose_key.get(COSE_KEY_COMMON_KTY) == COSE_KTY_OKP
            and cose_key.get(COSE_KEY_COMMON_ALG) == self.value
            and cose_key.get(COSE_KEY_OKP_CRV) == self.curve_number
            and COSE_KEY_OKP_X in cose_key
        ):
            return cose_key[COSE_KEY_OKP_X]
        else:
            raise ValueError("Key type not recognized from CCS key %r" % cose_key)

    value = -8
    curve_number = 6

    signature_length = 64


class EcdhSsHkdf256(AlgorithmStaticStatic):
    # FIXME: This class uses the Edwards keys as private and public keys, and
    # not the converted ones. This will be problematic if pairwise-only
    # contexts are to be set up.

    value = -27

    # FIXME these two will be different when using the Montgomery keys directly

    # This one will only be used when establishing and distributing pairwise-only keys
    public_from_private = Ed25519.public_from_private

    def staticstatic(self, private_key, public_key):
        private_key = asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(
            private_key
        )
        private_key = cryptography_additions.sk_to_curve25519(private_key)

        public_key = asymmetric.ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        public_key = cryptography_additions.pk_to_curve25519(public_key)

        return private_key.exchange(public_key)


class ECDSA_SHA256_P256(AlgorithmCountersign, AlgorithmStaticStatic):
    # Trying a new construction approach -- should work just as well given
    # we're just passing Python objects around
    def from_public_parts(self, x: bytes, y: bytes):
        """Create a public key from its COSE values"""
        return asymmetric.ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            asymmetric.ec.SECP256R1(),
        ).public_key()

    def from_kccs(self, ccs: bytes) -> Any:
        cose_key = _from_kccs_common(ccs)

        if (
            cose_key.get(COSE_KEY_COMMON_KTY) == COSE_KTY_EC2
            and cose_key.get(COSE_KEY_COMMON_ALG) == self.value
            and COSE_KEY_EC2_X in cose_key
            and COSE_KEY_EC2_Y in cose_key
        ):
            return self.from_public_parts(
                x=cose_key[COSE_KEY_EC2_X],
                y=cose_key[COSE_KEY_EC2_Y],
            )
        else:
            raise ValueError("Key type not recognized from CCS key %r" % cose_key)

    def from_private_parts(self, x: bytes, y: bytes, d: bytes):
        public_numbers = self.from_public_parts(x, y).public_numbers()
        private_numbers = asymmetric.ec.EllipticCurvePrivateNumbers(
            int.from_bytes(d, "big"), public_numbers
        )
        return private_numbers.private_key()

    def sign(self, body, aad, private_key):
        der_signature = private_key.sign(
            self._build_countersign_structure(body, aad),
            asymmetric.ec.ECDSA(hashes.SHA256()),
        )
        (r, s) = decode_dss_signature(der_signature)

        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(self, signature, body, aad, public_key):
        r = signature[:32]
        s = signature[32:]
        r = int.from_bytes(r, "big")
        s = int.from_bytes(s, "big")
        der_signature = encode_dss_signature(r, s)
        try:
            public_key.verify(
                der_signature,
                self._build_countersign_structure(body, aad),
                asymmetric.ec.ECDSA(hashes.SHA256()),
            )
        except cryptography.exceptions.InvalidSignature:
            raise ProtectionInvalid("Signature mismatch")

    def _generate(self):
        return asymmetric.ec.generate_private_key(asymmetric.ec.SECP256R1())

    def generate_with_ccs(self) -> Tuple[Any, bytes]:
        private = self._generate()
        public = self.public_from_private(private)
        # FIXME: Deduplicate with edhoc.py
        x = public.public_numbers().x.to_bytes(32, "big")
        y = public.public_numbers().y.to_bytes(32, "big")

        ccs = cbor.dumps(
            {
                CWT_CLAIM_CNF: {
                    CWT_CNF_COSE_KEY: {
                        COSE_KEY_COMMON_KTY: COSE_KTY_EC2,
                        COSE_KEY_COMMON_ALG: self.value,
                        COSE_KEY_EC2_X: x,
                        COSE_KEY_EC2_Y: y,
                    }
                }
            }
        )

        return (private, ccs)

    def public_from_private(self, private_key):
        return private_key.public_key()

    def staticstatic(self, private_key, public_key):
        return private_key.exchange(asymmetric.ec.ECDH(), public_key)

    value = -7  # FIXME: when used as a static-static algorithm, does this become -27? see shepherd review.
    curve_number = 1

    signature_length = 64


algorithms = {
    "AES-CCM-16-64-128": AES_CCM_16_64_128(),
    "AES-CCM-16-64-256": AES_CCM_16_64_256(),
    "AES-CCM-64-64-128": AES_CCM_64_64_128(),
    "AES-CCM-64-64-256": AES_CCM_64_64_256(),
    "AES-CCM-16-128-128": AES_CCM_16_128_128(),
    "AES-CCM-16-128-256": AES_CCM_16_128_256(),
    "AES-CCM-64-128-128": AES_CCM_64_128_128(),
    "AES-CCM-64-128-256": AES_CCM_64_128_256(),
    "ChaCha20/Poly1305": ChaCha20Poly1305(),
    "A128GCM": A128GCM(),
    "A192GCM": A192GCM(),
    "A256GCM": A256GCM(),
    "A128CBC": A128CBC(),
}

# algorithms with full parameter set
algorithms_countersign = {
    # maybe needs a different name...
    "EdDSA on Ed25519": Ed25519(),
    "ECDSA w/ SHA-256 on P-256": ECDSA_SHA256_P256(),
}

algorithms_staticstatic = {
    "ECDH-SS + HKDF-256": EcdhSsHkdf256(),
}

DEFAULT_ALGORITHM = "AES-CCM-16-64-128"

_hash_backend = cryptography.hazmat.backends.default_backend()
hashfunctions = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}

DEFAULT_HASHFUNCTION = "sha256"

DEFAULT_WINDOWSIZE = 32


class BaseSecurityContext:
    # Deprecated marker for whether the class uses the
    # ContextWhereExternalAadIsGroup mixin; see documentation there.
    external_aad_is_group = False

    # Authentication information carried with this security context; managed
    # externally by whatever creates the security context.
    authenticated_claims: List[str] = []

    #: AEAD algorithm. This may be None if it is not set in an OSCORE group context.
    alg_aead: Optional[AeadAlgorithm]

    #: The common IV of the common context.
    #:
    #: This may be longer than needed for constructing IVs with any particular
    #: algorithm, as per <https://www.ietf.org/archive/id/draft-ietf-core-oscore-groupcomm-23.html#section-2.1.4>
    common_iv: bytes

    id_context: Optional[bytes]

    @property
    def algorithm(self):
        warnings.warn(
            "Property was renamed to 'alg_aead'", DeprecationWarning, stacklevel=2
        )
        return self.alg_aead

    @algorithm.setter
    def algorithm(self, value):
        warnings.warn(
            "Property was renamed to 'alg_aead'", DeprecationWarning, stacklevel=2
        )
        self.alg_aead = value

    hashfun: hashes.HashAlgorithm

    def _construct_nonce(
        self, partial_iv_short, piv_generator_id, alg: SymmetricEncryptionAlgorithm
    ):
        pad_piv = b"\0" * (5 - len(partial_iv_short))

        s = bytes([len(piv_generator_id)])
        pad_id = b"\0" * (alg.iv_bytes - 6 - len(piv_generator_id))

        components = s + pad_id + piv_generator_id + pad_piv + partial_iv_short

        used_common_iv = self.common_iv[: len(components)]
        nonce = _xor_bytes(used_common_iv, components)
        _alglog.debug(
            "Nonce construction: common %s ^ components %s = %s",
            self.common_iv.hex(),
            components.hex(),
            nonce.hex(),
        )

        return nonce

    def _extract_external_aad(
        self, message, request_id, local_is_sender: bool
    ) -> bytes:
        """Build the serialized external AAD from information in the message
        and the request_id.

        Information about whether the local context is the sender of the
        message is only relevant to group contexts, where it influences whose
        authentication credentials are placed in the AAD.
        """
        # If any option were actually Class I, it would be something like
        #
        # the_options = pick some of(message)
        # class_i_options = Message(the_options).opt.encode()

        oscore_version = 1
        class_i_options = b""
        if request_id.request_hash is not None:
            class_i_options = Message(request_hash=request_id.request_hash).opt.encode()

        algorithms: List[int | str | None] = [
            None if self.alg_aead is None else self.alg_aead.value
        ]
        if isinstance(self, ContextWhereExternalAadIsGroup):
            algorithms.append(
                None if self.alg_group_enc is None else self.alg_group_enc.value
            )
            algorithms.append(
                None if self.alg_signature is None else self.alg_signature.value
            )
            algorithms.append(
                None
                if self.alg_pairwise_key_agreement is None
                else self.alg_pairwise_key_agreement.value
            )

        external_aad = [
            oscore_version,
            algorithms,
            request_id.kid,
            request_id.partial_iv,
            class_i_options,
        ]

        if isinstance(self, ContextWhereExternalAadIsGroup):
            # FIXME: We may need to carry this over in the request_id when
            # observation span group rekeyings
            external_aad.append(self.id_context)

            assert message.opt.oscore is not None, "Double OSCORE"
            external_aad.append(message.opt.oscore)

            if local_is_sender:
                external_aad.append(self.sender_auth_cred)
            else:
                external_aad.append(self.recipient_auth_cred)
            external_aad.append(self.group_manager_cred)

        return cbor.dumps(external_aad)


class ContextWhereExternalAadIsGroup(BaseSecurityContext):
    """The protection and unprotection functions will use the Group OSCORE AADs
    rather than the regular OSCORE AADs iff a context uses this mixin. (Ie.
    alg_group_enc etc are added to the algorithms, and request_kid_context,
    OSCORE_option, sender_auth_cred and gm_cred are added).

    This does not necessarily match the is_signing property (as pairwise
    contexts use this but don't sign), and is distinct from the added OSCORE
    option in the AAD (as that's only applicable for the external AAD as
    extracted for signing and signature verification purposes)."""

    id_context: bytes

    external_aad_is_group = True

    alg_group_enc: Optional[SymmetricEncryptionAlgorithm]
    alg_signature: Optional[AlgorithmCountersign]
    # This is also of type AlgorithmCountersign because the staticstatic
    # function is sitting on the same type.
    alg_pairwise_key_agreement: Optional[AlgorithmCountersign]

    sender_auth_cred: bytes
    recipient_auth_cred: bytes
    group_manager_cred: bytes


# FIXME pull interface components from SecurityContext up here
class CanProtect(BaseSecurityContext, metaclass=abc.ABCMeta):
    # The protection function will add a signature acccording to the context's
    # alg_signature attribute if this is true
    is_signing = False

    # Send the KID when protecting responses
    #
    # Once group pairwise mode is implemented, this will need to become a
    # parameter to protect(), which is stored at the point where the incoming
    # context is turned into an outgoing context. (Currently, such a mechanism
    # isn't there yet, and oscore_wrapper protects responses with the very same
    # context they came in on).
    responses_send_kid = False

    #: The KID sent by this party when sending requests, or answering to group
    #: requests.
    sender_id: bytes

    @staticmethod
    def _compress(protected, unprotected, ciphertext):
        """Pack the untagged COSE_Encrypt0 object described by the *args
        into two bytestrings suitable for the Object-Security option and the
        message body"""

        if protected:
            raise RuntimeError(
                "Protection produced a message that has uncompressable fields."
            )

        piv = unprotected.pop(COSE_PIV, b"")
        if len(piv) > COMPRESSION_BITS_N:
            raise ValueError("Can't encode overly long partial IV")

        firstbyte = len(piv)
        if COSE_KID in unprotected:
            firstbyte |= COMPRESSION_BIT_K
            kid_data = unprotected.pop(COSE_KID)
        else:
            kid_data = b""

        if COSE_KID_CONTEXT in unprotected:
            firstbyte |= COMPRESSION_BIT_H
            kid_context = unprotected.pop(COSE_KID_CONTEXT)
            s = len(kid_context)
            if s > 255:
                raise ValueError("KID Context too long")
            s_kid_context = bytes((s,)) + kid_context
        else:
            s_kid_context = b""

        if COSE_COUNTERSIGNATURE0 in unprotected:
            firstbyte |= COMPRESSION_BIT_GROUP

            unprotected.pop(COSE_COUNTERSIGNATURE0)

            # ciphertext will eventually also get the countersignature, but
            # that happens later when the option is already processed.

        if unprotected:
            raise RuntimeError(
                "Protection produced a message that has uncompressable fields."
            )

        if firstbyte:
            option = bytes([firstbyte]) + piv + s_kid_context + kid_data
        else:
            option = b""

        return (option, ciphertext)

    def protect(self, message, request_id=None, *, kid_context=True):
        """Given a plain CoAP message, create a protected message that contains
        message's options in the inner or outer CoAP message as described in
        OSCOAP.

        If the message is a response to a previous message, the additional data
        from unprotecting the request are passed in as request_id. When
        request data is present, its partial IV is reused if possible. The
        security context's ID context is encoded in the resulting message
        unless kid_context is explicitly set to a False; other values for the
        kid_context can be passed in as byte string in the same parameter.
        """

        _alglog.debug(
            "Protecting message %s with context %s and request ID %s",
            message,
            self,
            request_id,
        )

        assert (request_id is None) == message.code.is_request(), (
            "Requestishness of code to protect does not match presence of request ID"
        )

        assert message.direction is Direction.OUTGOING

        outer_message, plaintext = self._split_message(message, request_id)

        outer_message.direction = Direction.OUTGOING
        # There are currently no properties that relate to OSCORE that'd need to be discarded.
        outer_message.transport_tuning = message.transport_tuning

        protected = {}
        nonce = None
        partial_iv_generated_by = None
        unprotected = {}
        if request_id is not None:
            partial_iv_generated_by, partial_iv_short = (
                request_id.get_reusable_kid_and_piv()
            )

        alg_symmetric = self.alg_group_enc if self.is_signing else self.alg_aead
        assert isinstance(alg_symmetric, AeadAlgorithm) or self.is_signing, (
            "Non-AEAD algorithms can only be used in signing modes."
        )

        if partial_iv_generated_by is None:
            nonce, partial_iv_short = self._build_new_nonce(alg_symmetric)
            partial_iv_generated_by = self.sender_id

            unprotected[COSE_PIV] = partial_iv_short
        else:
            nonce = self._construct_nonce(
                partial_iv_short, partial_iv_generated_by, alg_symmetric
            )

        if message.code.is_request():
            unprotected[COSE_KID] = self.sender_id

            request_id = RequestIdentifiers(
                self.sender_id,
                partial_iv_short,
                can_reuse_nonce=None,
                request_code=outer_message.code,
            )

            if kid_context is True:
                if self.id_context is not None:
                    unprotected[COSE_KID_CONTEXT] = self.id_context
            elif kid_context is not False:
                unprotected[COSE_KID_CONTEXT] = kid_context
        else:
            if self.responses_send_kid:
                unprotected[COSE_KID] = self.sender_id

        # Putting in a dummy value as the signature calculation will already need some of the compression result
        if self.is_signing:
            unprotected[COSE_COUNTERSIGNATURE0] = b""
        # FIXME: Running this twice quite needlessly (just to get the oscore option for sending)
        option_data, _ = self._compress(protected, unprotected, b"")

        outer_message.opt.oscore = option_data

        external_aad = self._extract_external_aad(
            outer_message, request_id, local_is_sender=True
        )

        aad = SymmetricEncryptionAlgorithm._build_encrypt0_structure(
            protected, external_aad
        )

        key = self._get_sender_key(outer_message, external_aad, plaintext, request_id)

        _alglog.debug("Encrypting Encrypt0:")
        _alglog.debug("* aad = %s", aad.hex())
        _alglog.debug("* nonce = %s", nonce.hex())
        _alglog.debug("* key = %s", log_secret(key.hex()))
        _alglog.debug("* algorithm = %s", alg_symmetric)
        ciphertext = alg_symmetric.encrypt(plaintext, aad, key, nonce)

        _alglog.debug("Produced ciphertext %s", ciphertext.hex())

        _, payload = self._compress(protected, unprotected, ciphertext)

        if self.is_signing:
            signature = self.alg_signature.sign(payload, external_aad, self.private_key)
            # This is bordering "it's OK to log it in plain", because a reader
            # of the log can access both the plaintext and the ciphertext, but
            # still, it is called a key.
            _alglog.debug(
                "Producing keystream from signature encryption key: %s",
                log_secret(self.signature_encryption_key.hex()),
            )
            keystream = self._kdf_for_keystreams(
                partial_iv_generated_by,
                partial_iv_short,
                self.signature_encryption_key,
                self.sender_id,
                INFO_TYPE_KEYSTREAM_REQUEST
                if message.code.is_request()
                else INFO_TYPE_KEYSTREAM_RESPONSE,
            )
            _alglog.debug("Keystream is %s", keystream.hex())
            encrypted_signature = _xor_bytes(signature, keystream)
            _alglog.debug("Encrypted signature %s", encrypted_signature.hex())
            payload += encrypted_signature
        outer_message.payload = payload

        # FIXME go through options section

        _alglog.debug(
            "Protecting the message succeeded, yielding ciphertext %s and request ID %s",
            outer_message,
            request_id,
        )
        # the request_id in the second argument should be discarded by the
        # caller when protecting a response -- is that reason enough for an
        # `if` and returning None?
        return outer_message, request_id

    def _get_sender_key(self, outer_message, aad, plaintext, request_id):
        """Customization hook of the protect function

        While most security contexts have a fixed sender key, deterministic
        requests need to shake up a few things. They need to modify the outer
        message, as well as the request_id as it will later be used to
        unprotect the response."""
        return self.sender_key

    def _split_message(self, message, request_id):
        """Given a protected message, return the outer message that contains
        all Class I and Class U options (but without payload or Object-Security
        option), and the encoded inner message that contains all Class E
        options and the payload.

        This leaves the messages' remotes unset."""

        if message.code.is_request():
            outer_host = message.opt.uri_host
            proxy_uri = message.opt.proxy_uri

            inner_message = message.copy(
                uri_host=None,
                uri_port=None,
                proxy_uri=None,
                proxy_scheme=None,
            )
            inner_message.remote = None

            if proxy_uri is not None:
                # Use set_request_uri to split up the proxy URI into its
                # components; extract, preserve and clear them.
                inner_message.set_request_uri(proxy_uri, set_uri_host=False)
                if inner_message.opt.proxy_uri is not None:
                    raise ValueError("Can not split Proxy-URI into options")
                outer_uri = inner_message.remote.uri_base
                inner_message.remote = None
                inner_message.opt.proxy_scheme = None

            if message.opt.observe is None:
                outer_code = POST
            else:
                outer_code = FETCH
        else:
            outer_host = None
            proxy_uri = None

            inner_message = message.copy()

            outer_code = request_id.code_style.response

        # no max-age because these are always successsful responses
        outer_message = Message(
            code=outer_code,
            uri_host=outer_host,
            observe=None if message.code.is_response() else message.opt.observe,
        )
        if proxy_uri is not None:
            outer_message.set_request_uri(outer_uri)

        plaintext = bytes([inner_message.code]) + inner_message.opt.encode()
        if inner_message.payload:
            plaintext += bytes([0xFF])
            plaintext += inner_message.payload

        return outer_message, plaintext

    def _build_new_nonce(self, alg: SymmetricEncryptionAlgorithm):
        """This implements generation of a new nonce, assembled as per Figure 5
        of draft-ietf-core-object-security-06. Returns the shortened partial IV
        as well."""
        seqno = self.new_sequence_number()

        partial_iv = seqno.to_bytes(5, "big")

        return (
            self._construct_nonce(partial_iv, self.sender_id, alg),
            partial_iv.lstrip(b"\0") or b"\0",
        )

    # sequence number handling

    def new_sequence_number(self):
        """Return a new sequence number; the implementation is responsible for
        never returning the same value twice in a given security context.

        May raise ContextUnavailable."""
        retval = self.sender_sequence_number
        if retval >= MAX_SEQNO:
            raise ContextUnavailable("Sequence number too large, context is exhausted.")
        self.sender_sequence_number += 1
        self.post_seqnoincrease()
        return retval

    # implementation defined

    @abc.abstractmethod
    def post_seqnoincrease(self):
        """Ensure that sender_sequence_number is stored"""
        raise

    def context_from_response(self, unprotected_bag) -> CanUnprotect:
        """When receiving a response to a request protected with this security
        context, pick the security context with which to unprotect the response
        given the unprotected information from the Object-Security option.

        This allow picking the right security context in a group response, and
        helps getting a new short-lived context for B.2 mode. The default
        behaivor is returning self.
        """

        # FIXME justify by moving into a mixin for CanProtectAndUnprotect
        return self  # type: ignore


class CanUnprotect(BaseSecurityContext):
    recipient_key: bytes

    def unprotect(self, protected_message, request_id=None):
        _alglog.debug(
            "Unprotecting message %s with context %s and request ID %s",
            protected_message,
            self,
            request_id,
        )

        assert (request_id is not None) == protected_message.code.is_response(), (
            "Requestishness of code to unprotect does not match presence of request ID"
        )
        is_response = protected_message.code.is_response()

        assert protected_message.direction is Direction.INCOMING

        # Set to a raisable exception on replay check failures; it will be
        # raised, but the package may still be processed in the course of Echo handling.
        replay_error = None

        protected_serialized, protected, unprotected, ciphertext = (
            self._extract_encrypted0(protected_message)
        )

        if protected:
            raise ProtectionInvalid("The protected field is not empty")

        # FIXME check for duplicate keys in protected

        if unprotected.pop(COSE_KID_CONTEXT, self.id_context) != self.id_context:
            # FIXME is this necessary?
            raise ProtectionInvalid("Sender ID context does not match")

        if unprotected.pop(COSE_KID, self.recipient_id) != self.recipient_id:
            # for most cases, this is caught by the session ID dispatch, but in
            # responses (where explicit sender IDs are atypical), this is a
            # valid check
            raise ProtectionInvalid("Sender ID does not match")

        if COSE_PIV not in unprotected:
            if not is_response:
                raise ProtectionInvalid("No sequence number provided in request")

            seqno = None  # sentinel for not striking out anyting
            partial_iv_short = request_id.partial_iv
            partial_iv_generated_by = request_id.kid
        else:
            partial_iv_short = unprotected.pop(COSE_PIV)
            partial_iv_generated_by = self.recipient_id

            seqno = int.from_bytes(partial_iv_short, "big")

            if not is_response:
                if not self.recipient_replay_window.is_initialized():
                    replay_error = ReplayError("Sequence number check unavailable")
                elif not self.recipient_replay_window.is_valid(seqno):
                    replay_error = ReplayError("Sequence number was re-used")

                if replay_error is not None and self.echo_recovery is None:
                    # Don't even try decoding if there is no reason to
                    raise replay_error

                request_id = RequestIdentifiers(
                    partial_iv_generated_by,
                    partial_iv_short,
                    can_reuse_nonce=replay_error is None,
                    request_code=protected_message.code,
                )

        external_aad = self._extract_external_aad(
            protected_message, request_id, local_is_sender=False
        )

        if unprotected.pop(COSE_COUNTERSIGNATURE0, None) is not None:
            try:
                alg_signature = self.alg_signature
            except NameError:
                raise DecodeError(
                    "Group messages can not be decoded with this non-group context"
                )

            siglen = alg_signature.signature_length
            if len(ciphertext) < siglen:
                raise DecodeError("Message too short for signature")
            encrypted_signature = ciphertext[-siglen:]

            _alglog.debug(
                "Producing keystream from signature encryption key: %s",
                log_secret(self.signature_encryption_key.hex()),
            )
            keystream = self._kdf_for_keystreams(
                partial_iv_generated_by,
                partial_iv_short,
                self.signature_encryption_key,
                self.recipient_id,
                INFO_TYPE_KEYSTREAM_REQUEST
                if protected_message.code.is_request()
                else INFO_TYPE_KEYSTREAM_RESPONSE,
            )
            _alglog.debug("Encrypted signature %s", encrypted_signature.hex())
            _alglog.debug("Keystream is %s", keystream.hex())
            signature = _xor_bytes(encrypted_signature, keystream)

            ciphertext = ciphertext[:-siglen]

            alg_signature.verify(
                signature, ciphertext, external_aad, self.recipient_public_key
            )

            alg_symmetric = self.alg_group_enc
        else:
            alg_symmetric = self.alg_aead

        if unprotected:
            raise DecodeError("Unsupported unprotected option")

        if (
            len(ciphertext) < self.alg_aead.tag_bytes + 1
        ):  # +1 assures access to plaintext[0] (the code)
            raise ProtectionInvalid("Ciphertext too short")

        enc_structure = ["Encrypt0", protected_serialized, external_aad]
        aad = cbor.dumps(enc_structure)

        key = self._get_recipient_key(protected_message, alg_symmetric)

        nonce = self._construct_nonce(
            partial_iv_short, partial_iv_generated_by, alg_symmetric
        )

        _alglog.debug("Decrypting Encrypt0:")
        _alglog.debug("* ciphertext = %s", ciphertext.hex())
        _alglog.debug("* aad = %s", aad.hex())
        _alglog.debug("* nonce = %s", nonce.hex())
        _alglog.debug("* key = %s", log_secret(key.hex()))
        _alglog.debug("* algorithm = %s", alg_symmetric)
        try:
            plaintext = alg_symmetric.decrypt(ciphertext, aad, key, nonce)
        except Exception as e:
            _alglog.debug("Unprotecting failed")
            raise e

        self._post_decrypt_checks(
            external_aad, plaintext, protected_message, request_id
        )

        if not is_response and seqno is not None and replay_error is None:
            self.recipient_replay_window.strike_out(seqno)

        # FIXME add options from unprotected

        unprotected_message = Message(code=plaintext[0])
        unprotected_message.payload = unprotected_message.opt.decode(plaintext[1:])
        unprotected_message.direction = Direction.INCOMING

        try_initialize = (
            not self.recipient_replay_window.is_initialized()
            and self.echo_recovery is not None
        )
        if try_initialize:
            if protected_message.code.is_request():
                # Either accept into replay window and clear replay error, or raise
                # something that can turn into a 4.01,Echo response
                if unprotected_message.opt.echo == self.echo_recovery:
                    self.recipient_replay_window.initialize_from_freshlyseen(seqno)
                    replay_error = None
                else:
                    raise ReplayErrorWithEcho(
                        secctx=self, request_id=request_id, echo=self.echo_recovery
                    )
            else:
                # We can initialize the replay window from a response as well.
                # The response is guaranteed fresh as it was AEAD-decoded to
                # match a request sent by this process.
                #
                # This is rare, as it only works when the server uses an own
                # sequence number, eg. when sending a notification or when
                # acting again on a retransmitted safe request whose response
                # it did not cache.
                #
                # Nothing bad happens if we can't make progress -- we just
                # don't initialize the replay window that wouldn't have been
                # checked for a response anyway.
                if seqno is not None:
                    self.recipient_replay_window.initialize_from_freshlyseen(seqno)

        if replay_error is not None:
            raise replay_error

        if unprotected_message.code.is_request():
            if protected_message.opt.observe != 0:
                unprotected_message.opt.observe = None
        else:
            if protected_message.opt.observe is not None:
                # -1 ensures that they sort correctly in later reordering
                # detection. Note that neither -1 nor high (>3 byte) sequence
                # numbers can be serialized in the Observe option, but they are
                # in this implementation accepted for passing around.
                unprotected_message.opt.observe = -1 if seqno is None else seqno

        _alglog.debug(
            "Unprotecting succeeded, yielding plaintext %s and request_id %s",
            unprotected_message,
            request_id,
        )
        return unprotected_message, request_id

    def _get_recipient_key(
        self, protected_message, algorithm: SymmetricEncryptionAlgorithm
    ):
        """Customization hook of the unprotect function

        While most security contexts have a fixed recipient key, group contexts
        have multiple, and deterministic requests build it on demand."""
        return self.recipient_key

    def _post_decrypt_checks(self, aad, plaintext, protected_message, request_id):
        """Customization hook of the unprotect function after decryption

        While most security contexts are good with the default checks,
        deterministic requests need to perform additional checks while AAD and
        plaintext information is still available, and modify the request_id for
        the later protection step of the response."""

    @staticmethod
    def _uncompress(option_data, payload):
        if option_data == b"":
            firstbyte = 0
        else:
            firstbyte = option_data[0]
            tail = option_data[1:]

        unprotected = {}

        if firstbyte & COMPRESSION_BITS_RESERVED:
            raise DecodeError("Protected data uses reserved fields")

        pivsz = firstbyte & COMPRESSION_BITS_N
        if pivsz:
            if len(tail) < pivsz:
                raise DecodeError("Partial IV announced but not present")
            unprotected[COSE_PIV] = tail[:pivsz]
            tail = tail[pivsz:]

        if firstbyte & COMPRESSION_BIT_H:
            # kid context hint
            s = tail[0]
            if len(tail) - 1 < s:
                raise DecodeError("Context hint announced but not present")
            tail = tail[1:]
            unprotected[COSE_KID_CONTEXT] = tail[:s]
            tail = tail[s:]

        if firstbyte & COMPRESSION_BIT_K:
            kid = tail
            unprotected[COSE_KID] = kid

        if firstbyte & COMPRESSION_BIT_GROUP:
            # Not really; As this is (also) used early on (before the KID
            # context is even known, because it's just getting extracted), this
            # is returning an incomplete value here and leaves it to the later
            # processing to strip the right number of bytes from the ciphertext
            unprotected[COSE_COUNTERSIGNATURE0] = PRESENT_BUT_NO_VALUE_YET

        return b"", {}, unprotected, payload

    @classmethod
    def _extract_encrypted0(cls, message):
        if message.opt.oscore is None:
            raise NotAProtectedMessage("No Object-Security option present", message)

        protected_serialized, protected, unprotected, ciphertext = cls._uncompress(
            message.opt.oscore, message.payload
        )
        return protected_serialized, protected, unprotected, ciphertext

    # implementation defined

    def context_for_response(self) -> CanProtect:
        """After processing a request with this context, with which security
        context should an outgoing response be protected? By default, it's the
        same context."""
        # FIXME: Is there any way in which the handler may want to influence
        # the decision taken here? Or would, then, the handler just call a more
        # elaborate but similar function when setting the response's remote
        # already?

        # FIXME justify by moving into a mixin for CanProtectAndUnprotect
        return self  # type: ignore


class SecurityContextUtils(BaseSecurityContext):
    def _kdf(
        self,
        salt,
        ikm,
        role_id,
        out_type,
        key_alg: Optional[SymmetricEncryptionAlgorithm] = None,
    ):
        """The HKDF as used to derive sender and recipient key and IV in
        RFC8613 Section 3.2.1, and analogously the Group Encryption Key of oscore-groupcomm.
        """

        _alglog.debug("Deriving through KDF:")
        _alglog.debug("* salt = %s", salt.hex() if salt else salt)
        _alglog.debug("* ikm = %s", log_secret(ikm.hex()))
        _alglog.debug("* role_id = %s", role_id.hex())
        _alglog.debug("* out_type = %r", out_type)
        _alglog.debug("* key_alg = %r", key_alg)

        # The field in info is called `alg_aead` defined in RFC8613, but in
        # group OSCORE something that's very clearly *not* alg_aead is put in
        # there.
        #
        # The rules about this come both from
        # https://www.ietf.org/archive/id/draft-ietf-core-oscore-groupcomm-23.html#section-2.3
        # and
        # https://www.ietf.org/archive/id/draft-ietf-core-oscore-groupcomm-23.html#section-2.1.9
        # but they produce the same outcome.
        if hasattr(self, "alg_group_enc") and self.alg_group_enc is not None:
            the_field_called_alg_aead = self.alg_group_enc.value
        else:
            assert self.alg_aead is not None, (
                "At least alg_aead or alg_group_enc needs to be set on a context."
            )
            the_field_called_alg_aead = self.alg_aead.value

        assert (key_alg is None) ^ (out_type == "Key")
        if out_type == "Key":
            # Duplicate assertion needed while mypy can not see that the assert
            # above the if is stricter than this.
            assert key_alg is not None
            out_bytes = key_alg.key_bytes
            the_field_called_alg_aead = key_alg.value
        elif out_type == "IV":
            assert self.alg_aead is not None, (
                "At least alg_aead or alg_group_enc needs to be set on a context."
            )
            out_bytes = max(
                (
                    a.iv_bytes
                    for a in [self.alg_aead, getattr(self, "alg_group_enc", None)]
                    if a is not None
                )
            )
        elif out_type == "SEKey":
            assert isinstance(self, GroupContext) and self.alg_group_enc is not None, (
                "SEKey derivation is only defined for group contexts with a group encryption algorithm."
            )
            # "While the obtained Signature Encryption Key is never used with
            # the Group Encryption Algorithm, its length was chosen to obtain a
            # matching level of security."
            out_bytes = self.alg_group_enc.key_bytes
        else:
            raise ValueError("Output type not recognized")

        _alglog.debug("* the_field_called_alg_aead = %s", the_field_called_alg_aead)

        info = [
            role_id,
            self.id_context,
            the_field_called_alg_aead,
            out_type,
            out_bytes,
        ]
        _alglog.debug("* info = %r", info)
        ret = self._kdf_lowlevel(salt, ikm, info, out_bytes)
        _alglog.debug("Derivation of %r produced %s", out_type, log_secret(ret.hex()))
        return ret

    def _kdf_for_keystreams(self, piv_generated_by, salt, ikm, role_id, out_type):
        """The HKDF as used to derive the keystreams of oscore-groupcomm."""

        out_bytes = self.alg_signature.signature_length

        assert out_type in (
            INFO_TYPE_KEYSTREAM_REQUEST,
            INFO_TYPE_KEYSTREAM_RESPONSE,
        ), "Output type not recognized"

        info = [
            piv_generated_by,
            self.id_context,
            out_type,
            out_bytes,
        ]
        return self._kdf_lowlevel(salt, ikm, info, out_bytes)

    def _kdf_lowlevel(self, salt: bytes, ikm: bytes, info: list, l: int) -> bytes:  # noqa: E741 (signature follows RFC definition)
        """The HKDF function as used in RFC8613 and oscore-groupcomm (notated
        there as ``something = HKDF(...)``

        Note that `info` typically contains `L` at some point.

        When `info` takes the conventional structure of pid, id_context,
        ald_aead, type, L], it may make sense to extend the `_kdf` function to
        support that case, or `_kdf_for_keystreams` for a different structure, as
        they are the more high-level tools."""
        hkdf = HKDF(
            algorithm=self.hashfun,
            length=l,
            salt=salt,
            info=cbor.dumps(info),
            backend=_hash_backend,
        )
        expanded = hkdf.derive(ikm)
        return expanded

    def derive_keys(self, master_salt, master_secret):
        """Populate sender_key, recipient_key and common_iv from the algorithm,
        hash function and id_context already configured beforehand, and from
        the passed salt and secret."""

        self.sender_key = self._kdf(
            master_salt, master_secret, self.sender_id, "Key", self.alg_aead
        )
        self.recipient_key = self._kdf(
            master_salt, master_secret, self.recipient_id, "Key", self.alg_aead
        )

        self.common_iv = self._kdf(master_salt, master_secret, b"", "IV")

    # really more of the Credentials interface

    def get_oscore_context_for(self, unprotected):
        """Return a sutiable context (most easily self) for an incoming request
        if its unprotected data (COSE_KID, COSE_KID_CONTEXT) fit its
        description. If it doesn't match, it returns None.

        The default implementation just strictly checks for whether kid and any
        kid context match (not matching if a local KID context is set but none
        is given in the request); modes like Group OSCORE can spin up aspect
        objects here.
        """
        if (
            unprotected.get(COSE_KID, None) == self.recipient_id
            and unprotected.get(COSE_KID_CONTEXT, None) == self.id_context
        ):
            return self


class ReplayWindow:
    """A regular replay window of a fixed size.

    It is implemented as an index and a bitfield (represented by an integer)
    whose least significant bit represents the seqyence number of the index,
    and a 1 indicates that a number was seen. No shenanigans around implicit
    leading ones (think floating point normalization) happen.

    >>> w = ReplayWindow(32, lambda: None)
    >>> w.initialize_empty()
    >>> w.strike_out(5)
    >>> w.is_valid(3)
    True
    >>> w.is_valid(5)
    False
    >>> w.strike_out(0)
    >>> w.strike_out(1)
    >>> w.strike_out(2)
    >>> w.is_valid(1)
    False

    Jumping ahead by the window size invalidates older numbers:

    >>> w.is_valid(4)
    True
    >>> w.strike_out(35)
    >>> w.is_valid(4)
    True
    >>> w.strike_out(36)
    >>> w.is_valid(4)
    False

    Usage safety
    ------------

    For every key, the replay window can only be initielized empty once. On
    later uses, it needs to be persisted by storing the output of
    self.persist() somewhere and loaded from that persisted data.

    It is acceptable to store persistance data in the strike_out_callback, but
    that must then ensure that the data is written (flushed to a file or
    committed to a database), but that is usually inefficient.

    Stability
    ---------

    This class is not considered for stabilization yet and an implementation
    detail of the SecurityContext implementation(s).
    """

    _index = None
    """Sequence number represented by the least significant bit of _bitfield"""
    _bitfield = None
    """Integer interpreted as a bitfield, self._size wide. A digit 1 at any bit
    indicates that the bit's index (its power of 2) plus self._index was
    already seen."""

    def __init__(self, size, strike_out_callback):
        self._size = size
        self.strike_out_callback = strike_out_callback

    def is_initialized(self):
        return self._index is not None

    def initialize_empty(self):
        self._index = 0
        self._bitfield = 0

    def initialize_from_persisted(self, persisted):
        self._index = persisted["index"]
        self._bitfield = persisted["bitfield"]

    def initialize_from_freshlyseen(self, seen):
        """Initialize the replay window with a particular value that is just
        being observed in a fresh (ie. generated by the peer later than any
        messages processed before state was lost here) message. This marks the
        seen sequence number and all preceding it as invalid, and and all later
        ones as valid."""
        self._index = seen
        self._bitfield = 1

    def is_valid(self, number):
        if number < self._index:
            return False
        if number >= self._index + self._size:
            return True
        return (self._bitfield >> (number - self._index)) & 1 == 0

    def strike_out(self, number):
        if not self.is_valid(number):
            raise ValueError(
                "Sequence number is not valid any more and "
                "thus can't be removed from the window"
            )
        overshoot = number - (self._index + self._size - 1)
        if overshoot > 0:
            self._index += overshoot
            self._bitfield >>= overshoot
        assert self.is_valid(number), "Sequence number was not valid before strike-out"
        self._bitfield |= 1 << (number - self._index)

        self.strike_out_callback()

    def persist(self):
        """Return a dict containing internal state which can be passed to init
        to recreated the replay window."""

        return {"index": self._index, "bitfield": self._bitfield}


class FilesystemSecurityContext(
    CanProtect, CanUnprotect, SecurityContextUtils, credentials._Objectish
):
    """Security context stored in a directory as distinct files containing
    containing

    * Master secret, master salt, sender and recipient ID,
      optionally algorithm, the KDF hash function, and replay window size
      (settings.json and secrets.json, where the latter is typically readable
      only for the user)
    * sequence numbers and replay windows (sequence.json, the only file the
      process needs write access to)

    The static parameters can all either be placed in settings.json or
    secrets.json, but must not be present in both; the presence of either file
    is sufficient.

    .. warning::

        Security contexts must never be copied around and used after another
        copy was used. They should only ever be moved, and if they are copied
        (eg. as a part of a system backup), restored contexts must not be used
        again; they need to be replaced with freshly created ones.

    An additional file named `lock` is created to prevent the accidental use of
    a context by to concurrent programs.

    Note that the sequence number file is updated in an atomic fashion which
    requires file creation privileges in the directory. If privilege separation
    between settings/key changes and sequence number changes is desired, one
    way to achieve that on Linux is giving the aiocoap process's user group
    write permissions on the directory and setting the sticky bit on the
    directory, thus forbidding the user to remove the settings/secret files not
    owned by him.

    Writes due to sent sequence numbers are reduced by applying a variation on
    the mechanism of RFC8613 Appendix B.1.1 (incrementing the persisted sender
    seqence number in steps of `k`). That value is automatically grown from
    sequence_number_chunksize_start up to sequence_number_chunksize_limit.
    At runtime, the receive window is not stored but kept indeterminate. In
    case of an abnormal shutdown, the server uses the mechanism described in
    Appendix B.1.2 to recover.
    """

    # possibly overridden in constructor
    #
    # Type is ignored because while it *is* AlgAead, mypy can't tell.
    alg_aead = algorithms[DEFAULT_ALGORITHM]  # type: ignore

    class LoadError(ValueError):
        """Exception raised with a descriptive message when trying to load a
        faulty security context"""

    def __init__(
        self,
        basedir: str,
        sequence_number_chunksize_start=10,
        sequence_number_chunksize_limit=10000,
    ):
        self.basedir = basedir

        self.lockfile: Optional[filelock.FileLock] = filelock.FileLock(
            os.path.join(basedir, "lock")
        )
        # 0.001: Just fail if it can't be acquired
        # See https://github.com/benediktschmitt/py-filelock/issues/57
        try:
            self.lockfile.acquire(timeout=0.001)
        # see https://github.com/PyCQA/pycodestyle/issues/703
        except:  # noqa: E722
            # No lock, no loading, no need to fail in __del__
            self.lockfile = None
            raise

        # Always enabled as committing to a file for every received request
        # would be a terrible burden.
        self.echo_recovery = secrets.token_bytes(8)

        try:
            self._load()
        except KeyError as k:
            raise self.LoadError("Configuration key missing: %s" % (k.args[0],))

        self.sequence_number_chunksize_start = sequence_number_chunksize_start
        self.sequence_number_chunksize_limit = sequence_number_chunksize_limit
        self.sequence_number_chunksize = sequence_number_chunksize_start

        self.sequence_number_persisted = self.sender_sequence_number

    def _load(self):
        # doesn't check for KeyError on every occasion, relies on __init__ to
        # catch that

        data = {}
        for readfile in ("secret.json", "settings.json"):
            try:
                with open(os.path.join(self.basedir, readfile)) as f:
                    filedata = json.load(f)
            except FileNotFoundError:
                continue

            for key, value in filedata.items():
                if key.endswith("_hex"):
                    key = key[:-4]
                    value = binascii.unhexlify(value)
                elif key.endswith("_ascii"):
                    key = key[:-6]
                    value = value.encode("ascii")

                if key in data:
                    raise self.LoadError(
                        "Datum %r present in multiple input files at %r."
                        % (key, self.basedir)
                    )

                data[key] = value

        self.alg_aead = algorithms[data.get("algorithm", DEFAULT_ALGORITHM)]
        self.hashfun = hashfunctions[data.get("kdf-hashfun", DEFAULT_HASHFUNCTION)]

        windowsize = data.get("window", DEFAULT_WINDOWSIZE)
        if not isinstance(windowsize, int):
            raise self.LoadError("Non-integer replay window")

        self.sender_id = data["sender-id"]
        self.recipient_id = data["recipient-id"]

        if (
            max(len(self.sender_id), len(self.recipient_id))
            > self.alg_aead.iv_bytes - 6
        ):
            raise self.LoadError(
                "Sender or Recipient ID too long (maximum length %s for this algorithm)"
                % (self.alg_aead.iv_bytes - 6)
            )

        master_secret = data["secret"]
        master_salt = data.get("salt", b"")
        self.id_context = data.get("id-context", None)

        self.derive_keys(master_salt, master_secret)

        self.recipient_replay_window = ReplayWindow(
            windowsize, self._replay_window_changed
        )
        try:
            with open(os.path.join(self.basedir, "sequence.json")) as f:
                sequence = json.load(f)
        except FileNotFoundError:
            self.sender_sequence_number = 0
            self.recipient_replay_window.initialize_empty()
            self.replay_window_persisted = True
        else:
            self.sender_sequence_number = int(sequence["next-to-send"])
            received = sequence["received"]
            if received == "unknown":
                # The replay window will stay uninitialized, which triggers
                # Echo recovery
                self.replay_window_persisted = False
            else:
                try:
                    self.recipient_replay_window.initialize_from_persisted(received)
                except (ValueError, TypeError, KeyError):
                    # Not being particularly careful about what could go wrong: If
                    # someone tampers with the replay data, we're already in *big*
                    # trouble, of which I fail to see how it would become worse
                    # than a crash inside the application around "failure to
                    # right-shift a string" or that like; at worst it'd result in
                    # nonce reuse which tampering with the replay window file
                    # already does.
                    raise self.LoadError(
                        "Persisted replay window state was not understood"
                    )
                self.replay_window_persisted = True

    # This is called internally whenever a new sequence number is taken or
    # crossed out from the window, and blocks a lot; B.1 mode mitigates that.
    #
    # Making it async and block in a threadpool would mitigate the blocking of
    # other messages, but the more visible effect of this will be that no
    # matter if sync or async, a reply will need to wait for a file sync
    # operation to conclude.
    def _store(self):
        tmphand, tmpnam = tempfile.mkstemp(
            dir=self.basedir, prefix=".sequence-", suffix=".json", text=True
        )

        data = {"next-to-send": self.sequence_number_persisted}
        if not self.replay_window_persisted:
            data["received"] = "unknown"
        else:
            data["received"] = self.recipient_replay_window.persist()

        # Using io.open (instead os.fdopen) and binary / write with encode
        # rather than dumps as that works even while the interpreter is
        # shutting down.
        #
        # This can be relaxed when there is a defined shutdown sequence for
        # security contexts that's triggered from the general context shutdown
        # -- but right now, there isn't.
        with io.open(tmphand, "wb") as tmpfile:
            tmpfile.write(json.dumps(data).encode("utf8"))
            tmpfile.flush()
            os.fsync(tmpfile.fileno())

        os.replace(tmpnam, os.path.join(self.basedir, "sequence.json"))

    def _replay_window_changed(self):
        if self.replay_window_persisted:
            # Just remove the sequence numbers once from the file
            self.replay_window_persisted = False
            self._store()

    def post_seqnoincrease(self):
        if self.sender_sequence_number > self.sequence_number_persisted:
            self.sequence_number_persisted += self.sequence_number_chunksize

            self.sequence_number_chunksize = min(
                self.sequence_number_chunksize * 2, self.sequence_number_chunksize_limit
            )
            # FIXME: this blocks -- see https://github.com/chrysn/aiocoap/issues/178
            self._store()

            # The = case would only happen if someone deliberately sets all
            # numbers to 1 to force persisting on every step
            assert self.sender_sequence_number <= self.sequence_number_persisted, (
                "Using a sequence number that has been persisted already"
            )

    def _destroy(self):
        """Release the lock file, and ensure tha he object has become
        unusable.

        If there is unpersisted state from B.1 operation, the actually used
        number and replay window gets written back to the file to allow
        resumption without wasting digits or round-trips.
        """
        # FIXME: Arrange for a more controlled shutdown through the credentials

        self.replay_window_persisted = True
        self.sequence_number_persisted = self.sender_sequence_number
        self._store()

        del self.sender_key
        del self.recipient_key

        os.unlink(self.lockfile.lock_file)
        self.lockfile.release()

        self.lockfile = None

    def __del__(self):
        if self.lockfile is not None:
            self._destroy()

    @classmethod
    def from_item(cls, init_data):
        """Overriding _Objectish's from_item because the parameter name for
        basedir is contextfile for historical reasons"""

        def constructor(
            basedir: Optional[str] = None, contextfile: Optional[str] = None
        ):
            if basedir is not None and contextfile is not None:
                raise credentials.CredentialsLoadError(
                    "Conflicting arguments basedir and contextfile; just contextfile instead"
                )
            if basedir is None and contextfile is None:
                raise credentials.CredentialsLoadError("Missing item 'basedir'")
            if contextfile is not None:
                warnings.warn(
                    "Property contextfile was renamed to basedir in OSCORE credentials entries",
                    DeprecationWarning,
                    stacklevel=2,
                )
                basedir = contextfile
            assert (
                basedir is not None
            )  # This helps mypy which would otherwise not see that the above ensures this already
            return cls(basedir)

        return credentials._call_from_structureddata(
            constructor, cls.__name__, init_data
        )

    def find_all_used_contextless_oscore_kid(self) -> set[bytes]:
        return set((self.recipient_id,))


class GroupContext(ContextWhereExternalAadIsGroup, BaseSecurityContext):
    is_signing = True
    responses_send_kid = True

    @abc.abstractproperty
    def private_key(self):
        """Private key used to sign outgoing messages.

        Contexts not designed to send messages may raise a RuntimeError here;
        that necessity may later go away if some more accurate class modelling
        is found."""

    @abc.abstractproperty
    def recipient_public_key(self):
        """Public key used to verify incoming messages.

        Contexts not designed to receive messages (because they'd have aspects
        for that) may raise a RuntimeError here; that necessity may later go
        away if some more accurate class modelling is found."""


class SimpleGroupContext(GroupContext, CanProtect, CanUnprotect, SecurityContextUtils):
    """A context for an OSCORE group

    This is a non-persistable version of a group context that does not support
    any group manager or rekeying; it is set up statically at startup.

    It is intended for experimentation and demos, but aims to be correct enough
    to be usable securely.
    """

    # set during initialization (making all those attributes rather than
    # possibly properties as they might be in super)
    sender_id = None  # type: ignore
    id_context = None  # type: ignore
    private_key = None
    alg_aead = None
    hashfun = None  # type: ignore
    alg_signature = None
    alg_group_enc = None
    alg_pairwise_key_agreement = None
    sender_auth_cred = None  # type: ignore
    group_manager_cred = None  # type: ignore
    cred_fmt = None
    # This is currently not evaluated, but any GM interaction will need to have this information available.
    group_manager_cred_fmt = None

    def __init__(
        self,
        alg_aead,
        hashfun,
        alg_signature,
        alg_group_enc,
        alg_pairwise_key_agreement,
        group_id,
        master_secret,
        master_salt,
        sender_id,
        private_key,
        sender_auth_cred,
        peers,
        group_manager_cred,
        cred_fmt=COSE_KCCS,
        group_manager_cred_fmt=COSE_KCCS,
    ):
        self.sender_id = sender_id
        self.id_context = group_id
        self.private_key = private_key
        self.alg_aead = alg_aead
        self.hashfun = hashfun
        self.alg_signature = alg_signature
        self.alg_group_enc = alg_group_enc
        self.alg_pairwise_key_agreement = alg_pairwise_key_agreement
        self.sender_auth_cred = sender_auth_cred
        self.group_manager_cred = group_manager_cred
        self.cred_fmt = cred_fmt
        self.group_manager_cred_fmt = group_manager_cred_fmt

        self.peers = peers.keys()
        self.recipient_public_keys = {
            k: self._parse_credential(v) for (k, v) in peers.items()
        }
        self.recipient_auth_creds = peers
        self.recipient_replay_windows = {}
        for k in self.peers:
            # no need to persist, the whole group is ephemeral
            w = ReplayWindow(32, lambda: None)
            w.initialize_empty()
            self.recipient_replay_windows[k] = w

        self.derive_keys(master_salt, master_secret)
        self.sender_sequence_number = 0

        sender_public_key = self._parse_credential(sender_auth_cred)
        if (
            self.alg_signature.public_from_private(self.private_key)
            != sender_public_key
        ):
            raise ValueError(
                "The key in the provided sender credential does not match the private key"
            )

    def _parse_credential(self, credential: bytes | _DeterministicKey):
        """Extract the public key (in the public_key format the respective
        AlgorithmCountersign needs) from credentials. This raises a ValueError
        if the credentials do not match the group's cred_fmt, or if the
        parameters do not match those configured in the group.

        This currently discards any information that is present in the
        credential that exceeds the key. (In a future version, this could
        return both the key and extracted other data, where that other data
        would be stored with the peer this is parsed from).
        """

        if credential is DETERMINISTIC_KEY:
            return credential

        if self.cred_fmt != COSE_KCCS:
            raise ValueError(
                "Credential parsing is currently only implemented for CCSs"
            )

        assert self.alg_signature is not None

        return self.alg_signature.from_kccs(credential)

    def __repr__(self):
        return "<%s with group %r sender_id %r and %d peers>" % (
            type(self).__name__,
            self.id_context.hex(),
            self.sender_id.hex(),
            len(self.peers),
        )

    @property
    def recipient_public_key(self):
        raise RuntimeError(
            "Group context without key indication was used for verification"
        )

    def _get_sender_key(self, outer_message, aad, plaintext, request_id):
        # If we even get here, there has to be a alg_group_enc, and thus the sender key does match it
        return self._sender_key

    def derive_keys(self, master_salt, master_secret):
        the_main_alg = (
            self.alg_group_enc if self.alg_group_enc is not None else self.alg_aead
        )

        self._sender_key = self._kdf(
            master_salt, master_secret, self.sender_id, "Key", the_main_alg
        )
        self.recipient_keys = {
            recipient_id: self._kdf(
                master_salt, master_secret, recipient_id, "Key", the_main_alg
            )
            for recipient_id in self.peers
        }

        self.common_iv = self._kdf(master_salt, master_secret, b"", "IV")

        self.signature_encryption_key = self._kdf(
            master_salt, master_secret, b"", "SEKey"
        )

    def post_seqnoincrease(self):
        """No-op because it's ephemeral"""

    def context_from_response(self, unprotected_bag) -> CanUnprotect:
        # sender ID *needs to be* here -- if this were a pairwise request, it
        # would not run through here
        try:
            sender_kid = unprotected_bag[COSE_KID]
        except KeyError:
            raise DecodeError("Group server failed to send own sender KID")

        if COSE_COUNTERSIGNATURE0 in unprotected_bag:
            return _GroupContextAspect(self, sender_kid)
        else:
            return _PairwiseContextAspect(self, sender_kid)

    def get_oscore_context_for(self, unprotected):
        if unprotected.get(COSE_KID_CONTEXT, None) != self.id_context:
            return None

        kid = unprotected.get(COSE_KID, None)
        if kid in self.peers:
            if COSE_COUNTERSIGNATURE0 in unprotected:
                return _GroupContextAspect(self, kid)
            elif self.recipient_public_keys[kid] is DETERMINISTIC_KEY:
                return _DeterministicUnprotectProtoAspect(self, kid)
            else:
                return _PairwiseContextAspect(self, kid)

    def find_all_used_contextless_oscore_kid(self) -> set[bytes]:
        # not conflicting: groups always send KID Context
        return set()

    # yet to stabilize...

    def pairwise_for(self, recipient_id):
        return _PairwiseContextAspect(self, recipient_id)

    def for_sending_deterministic_requests(
        self, deterministic_id, target_server: Optional[bytes]
    ):
        return _DeterministicProtectProtoAspect(self, deterministic_id, target_server)


class _GroupContextAspect(GroupContext, CanUnprotect, SecurityContextUtils):
    """The concrete context this host has with a particular peer

    As all actual data is stored in the underlying groupcontext, this acts as
    an accessor to that object (which picks the right recipient key).

    This accessor is for receiving messages in group mode from a particular
    peer; it does not send (and turns into a pairwise context through
    context_for_response before it comes to that).
    """

    def __init__(self, groupcontext: GroupContext, recipient_id: bytes) -> None:
        self.groupcontext = groupcontext
        self.recipient_id = recipient_id

    def __repr__(self):
        return "<%s inside %r with the peer %r>" % (
            type(self).__name__,
            self.groupcontext,
            self.recipient_id.hex(),
        )

    private_key = None

    # not inline because the equivalent lambda would not be recognized by mypy
    # (workaround for <https://github.com/python/mypy/issues/8083>)
    @property
    def id_context(self):
        return self.groupcontext.id_context

    @property
    def alg_aead(self):
        return self.groupcontext.alg_aead

    @property
    def alg_signature(self):
        return self.groupcontext.alg_signature

    @property
    def alg_group_enc(self):
        return self.groupcontext.alg_group_enc

    @property
    def alg_pairwise_key_agreement(self):
        return self.groupcontext.alg_pairwise_key_agreement

    @property
    def group_manager_cred(self):
        return self.groupcontext.group_manager_cred

    @property
    def common_iv(self):
        return self.groupcontext.common_iv

    @property
    def hashfun(self):
        return self.groupcontext.hashfun

    @property
    def signature_encryption_key(self):
        return self.groupcontext.signature_encryption_key

    @property
    def recipient_key(self):
        # If we even get here, there has to be a alg_group_enc, and thus the recipient key does match it
        return self.groupcontext.recipient_keys[self.recipient_id]

    @property
    def recipient_public_key(self):
        return self.groupcontext.recipient_public_keys[self.recipient_id]

    @property
    def recipient_auth_cred(self):
        return self.groupcontext.recipient_auth_creds[self.recipient_id]

    @property
    def recipient_replay_window(self):
        return self.groupcontext.recipient_replay_windows[self.recipient_id]

    def context_for_response(self):
        return self.groupcontext.pairwise_for(self.recipient_id)

    @property
    def sender_auth_cred(self):
        raise RuntimeError(
            "Could relay the sender auth credential from the group context, but it shouldn't matter here"
        )


class _PairwiseContextAspect(
    GroupContext, CanProtect, CanUnprotect, SecurityContextUtils
):
    is_signing = False

    def __init__(self, groupcontext, recipient_id):
        self.groupcontext = groupcontext
        self.recipient_id = recipient_id

        shared_secret = self.alg_pairwise_key_agreement.staticstatic(
            self.groupcontext.private_key,
            self.groupcontext.recipient_public_keys[recipient_id],
        )

        self.sender_key = self._kdf(
            self.groupcontext._sender_key,
            (
                self.groupcontext.sender_auth_cred
                + self.groupcontext.recipient_auth_creds[recipient_id]
                + shared_secret
            ),
            self.groupcontext.sender_id,
            "Key",
            self.alg_group_enc if self.is_signing else self.alg_aead,
        )
        self.recipient_key = self._kdf(
            self.groupcontext.recipient_keys[recipient_id],
            (
                self.groupcontext.recipient_auth_creds[recipient_id]
                + self.groupcontext.sender_auth_cred
                + shared_secret
            ),
            self.recipient_id,
            "Key",
            self.alg_group_enc if self.is_signing else self.alg_aead,
        )

    def __repr__(self):
        return "<%s based on %r with the peer %r>" % (
            type(self).__name__,
            self.groupcontext,
            self.recipient_id.hex(),
        )

    # FIXME: actually, only to be sent in requests

    # not inline because the equivalent lambda would not be recognized by mypy
    # (workaround for <https://github.com/python/mypy/issues/8083>)
    @property
    def id_context(self):
        return self.groupcontext.id_context

    @property
    def alg_aead(self):
        return self.groupcontext.alg_aead

    @property
    def hashfun(self):
        return self.groupcontext.hashfun

    @property
    def alg_signature(self):
        return self.groupcontext.alg_signature

    @property
    def alg_group_enc(self):
        return self.groupcontext.alg_group_enc

    @property
    def alg_pairwise_key_agreement(self):
        return self.groupcontext.alg_pairwise_key_agreement

    @property
    def group_manager_cred(self):
        return self.groupcontext.group_manager_cred

    @property
    def common_iv(self):
        return self.groupcontext.common_iv

    @property
    def sender_id(self):
        return self.groupcontext.sender_id

    @property
    def recipient_auth_cred(self):
        return self.groupcontext.recipient_auth_creds[self.recipient_id]

    @property
    def sender_auth_cred(self):
        return self.groupcontext.sender_auth_cred

    @property
    def recipient_replay_window(self):
        return self.groupcontext.recipient_replay_windows[self.recipient_id]

    # Set at initialization (making all those attributes rather than
    # possibly properties as they might be in super)
    recipient_key = None  # type: ignore
    sender_key = None

    @property
    def sender_sequence_number(self):
        return self.groupcontext.sender_sequence_number

    @sender_sequence_number.setter
    def sender_sequence_number(self, new):
        self.groupcontext.sender_sequence_number = new

    def post_seqnoincrease(self):
        self.groupcontext.post_seqnoincrease()

    # same here -- not needed because not signing
    private_key = property(post_seqnoincrease)
    recipient_public_key = property(post_seqnoincrease)

    def context_from_response(self, unprotected_bag) -> CanUnprotect:
        if unprotected_bag.get(COSE_KID, self.recipient_id) != self.recipient_id:
            raise DecodeError(
                "Response coming from a different server than requested, not attempting to decrypt"
            )

        if COSE_COUNTERSIGNATURE0 in unprotected_bag:
            # It'd be an odd thing to do, but it's source verified, so the
            # server hopefully has reasons to make this readable to other group
            # members.
            return _GroupContextAspect(self.groupcontext, self.recipient_id)
        else:
            return self


class _DeterministicProtectProtoAspect(
    ContextWhereExternalAadIsGroup, CanProtect, SecurityContextUtils
):
    """This implements the sending side of Deterministic Requests.

    While simialr to a _PairwiseContextAspect, it only derives the key at
    protection time, as the plain text is hashed into the key."""

    deterministic_hashfun = hashes.SHA256()

    def __init__(self, groupcontext, sender_id, target_server: Optional[bytes]):
        self.groupcontext = groupcontext
        self.sender_id = sender_id
        self.target_server = target_server

    def __repr__(self):
        return "<%s based on %r with the sender ID %r%s>" % (
            type(self).__name__,
            self.groupcontext,
            self.sender_id.hex(),
            "limited to responses from %s" % self.target_server
            if self.target_server is not None
            else "",
        )

    def new_sequence_number(self):
        return 0

    def post_seqnoincrease(self):
        pass

    def context_from_response(self, unprotected_bag):
        if self.target_server is None:
            if COSE_KID not in unprotected_bag:
                raise DecodeError(
                    "Server did not send a KID and no particular one was addressed"
                )
        else:
            if unprotected_bag.get(COSE_KID, self.target_server) != self.target_server:
                raise DecodeError(
                    "Response coming from a different server than requested, not attempting to decrypt"
                )

        if COSE_COUNTERSIGNATURE0 not in unprotected_bag:
            # Could just as well pass and later barf when the group context doesn't find a signature
            raise DecodeError(
                "Response to deterministic request came from unsecure pairwise context"
            )

        return _GroupContextAspect(
            self.groupcontext, unprotected_bag.get(COSE_KID, self.target_server)
        )

    def _get_sender_key(self, outer_message, aad, plaintext, request_id):
        if outer_message.code.is_response():
            raise RuntimeError("Deterministic contexts shouldn't protect responses")

        basekey = self.groupcontext.recipient_keys[self.sender_id]

        h = hashes.Hash(self.deterministic_hashfun)
        h.update(basekey)
        h.update(aad)
        h.update(plaintext)
        request_hash = h.finalize()

        outer_message.opt.request_hash = request_hash
        outer_message.code = FETCH

        # By this time, the AADs have all been calculated already; setting this
        # for the benefit of the response parsing later
        request_id.request_hash = request_hash
        # FIXME I don't think this ever comes to bear but want to be sure
        # before removing this line (this should only be client-side)
        request_id.can_reuse_nonce = False
        # FIXME: we're still sending a h'00' PIV. Not wrong, just a wasted byte.

        return self._kdf(basekey, request_hash, self.sender_id, "Key", self.alg_aead)

    # details needed for various operations, especially eAAD generation

    @property
    def sender_auth_cred(self):
        # When preparing the external_aad, the element 'sender_cred' in the
        # aad_array takes the empty CBOR byte string (0x40).
        return b""

    # not inline because the equivalent lambda would not be recognized by mypy
    # (workaround for <https://github.com/python/mypy/issues/8083>)
    @property
    def alg_aead(self):
        return self.groupcontext.alg_aead

    @property
    def alg_group_enc(self):
        return self.groupcontext.alg_group_enc

    @property
    def alg_pairwise_key_agreement(self):
        return self.groupcontext.alg_pairwise_key_agreement

    @property
    def hashfun(self):
        return self.groupcontext.hashfun

    @property
    def common_iv(self):
        return self.groupcontext.common_iv

    @property
    def id_context(self):
        return self.groupcontext.id_context

    @property
    def alg_signature(self):
        return self.groupcontext.alg_signature

    @property
    def group_manager_cred(self):
        return self.groupcontext.group_manager_cred


class _DeterministicUnprotectProtoAspect(
    ContextWhereExternalAadIsGroup, CanUnprotect, SecurityContextUtils
):
    """This implements the sending side of Deterministic Requests.

    While simialr to a _PairwiseContextAspect, it only derives the key at
    unprotection time, based on information given as Request-Hash."""

    # Unless None, this is the value by which the running process recognizes
    # that the second phase of a B.1.2 replay window recovery Echo option comes
    # from the current process, and thus its sequence number is fresh
    echo_recovery = None

    deterministic_hashfun = hashes.SHA256()

    class ZeroIsAlwaysValid:
        """Special-purpose replay window that accepts 0 indefinitely"""

        def is_initialized(self):
            return True

        def is_valid(self, number):
            # No particular reason to be lax here
            return number == 0

        def strike_out(self, number):
            # FIXME: I'd rather indicate here that it's a potential replay, have the
            # request_id.can_reuse_nonce = False
            # set here rather than in _post_decrypt_checks, and thus also get
            # the check for whether it's a safe method
            pass

        def persist(self):
            pass

    def __init__(self, groupcontext, recipient_id):
        self.groupcontext = groupcontext
        self.recipient_id = recipient_id

        self.recipient_replay_window = self.ZeroIsAlwaysValid()

    def __repr__(self):
        return "<%s based on %r with the recipient ID %r>" % (
            type(self).__name__,
            self.groupcontext,
            self.recipient_id.hex(),
        )

    def context_for_response(self):
        return self.groupcontext

    def _get_recipient_key(self, protected_message, algorithm):
        logging.critical(
            "Deriving recipient key for protected message %s", protected_message
        )
        return self._kdf(
            self.groupcontext.recipient_keys[self.recipient_id],
            protected_message.opt.request_hash,
            self.recipient_id,
            "Key",
            algorithm,
        )

    def _post_decrypt_checks(self, aad, plaintext, protected_message, request_id):
        if plaintext[0] not in (GET, FETCH):  # FIXME: "is safe"
            # FIXME: accept but return inner Unauthorized. (Raising Unauthorized
            # here would just create an unprotected Unauthorized, which is not
            # what's spec'd for here)
            raise ProtectionInvalid("Request was not safe")

        basekey = self.groupcontext.recipient_keys[self.recipient_id]

        h = hashes.Hash(self.deterministic_hashfun)
        h.update(basekey)
        h.update(aad)
        h.update(plaintext)
        request_hash = h.finalize()

        if request_hash != protected_message.opt.request_hash:
            raise ProtectionInvalid(
                "Client's hash of the plaintext diverges from the actual request hash"
            )

        # This is intended for the protection of the response, and the
        # later use in signature in the unprotect function is not happening
        # here anyway, neither is the later use for Echo requests
        request_id.request_hash = request_hash
        request_id.can_reuse_nonce = False

    # details needed for various operations, especially eAAD generation

    @property
    def recipient_auth_cred(self):
        # When preparing the external_aad, the element 'sender_cred' in the
        # aad_array takes the empty CBOR byte string (0x40).
        return b""

    # not inline because the equivalent lambda would not be recognized by mypy
    # (workaround for <https://github.com/python/mypy/issues/8083>)
    @property
    def alg_aead(self):
        return self.groupcontext.alg_aead

    @property
    def alg_group_enc(self):
        return self.groupcontext.alg_group_enc

    @property
    def alg_pairwise_key_agreement(self):
        return self.groupcontext.alg_pairwise_key_agreement

    @property
    def hashfun(self):
        return self.groupcontext.hashfun

    @property
    def common_iv(self):
        return self.groupcontext.common_iv

    @property
    def id_context(self):
        return self.groupcontext.id_context

    @property
    def alg_signature(self):
        return self.groupcontext.alg_signature

    @property
    def group_manager_cred(self):
        return self.groupcontext.group_manager_cred


def verify_start(message):
    """Extract the unprotected COSE options from a
    message for the verifier to then pick a security context to actually verify
    the message. (Future versions may also report fields from both unprotected
    and protected, if the protected bag is ever used with OSCORE.).

    Call this only requests; for responses, you'll have to know the security
    context anyway, and there is usually no information to be gained."""

    _, _, unprotected, _ = CanUnprotect._extract_encrypted0(message)

    return unprotected


_getattr__ = deprecation_getattr(
    {
        "COSE_COUNTERSINGATURE0": "COSE_COUNTERSIGNATURE0",
        "Algorithm": "AeadAlgorithm",
    },
    globals(),
)
