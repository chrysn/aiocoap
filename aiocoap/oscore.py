# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains the tools to send OSCORE secured messages.

It only deals with the algorithmic parts, the security context and protection
and unprotection of messages. It does not touch on the integration of OSCORE in
the larger aiocoap stack of having a context or requests; that's what
:mod:`aiocoap.transports.osore` is for.`"""

import json
import binascii
import os, os.path
import warnings
import tempfile
import abc

from aiocoap.message import Message
from aiocoap.util import secrets
from aiocoap.numbers import POST, FETCH, CHANGED, UNAUTHORIZED
from aiocoap import error

from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import cryptography.hazmat.backends
import cryptography.exceptions

import cbor2 as cbor

import filelock

MAX_SEQNO = 2**40 - 1

# Relevant values from the IANA registry "CBOR Object Signing and Encryption (COSE)"
COSE_KID = 4
COSE_PIV = 6
COSE_KID_CONTEXT = 10

COMPRESSION_BITS_N = 0b111
COMPRESSION_BIT_K = 0b1000
COMPRESSION_BIT_H = 0b10000
COMPRESSION_BITS_RESERVED = 0b11100000

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
    def __init__(self, kid, partial_iv, nonce, can_reuse_nonce):
        self.kid = kid
        self.partial_iv = partial_iv
        self.nonce = nonce
        self.can_reuse_nonce = can_reuse_nonce

    def get_reusable_nonce(self):
        """Return the nonce if can_reuse_nonce is True, and set can_reuse_nonce
        to False."""

        if self.can_reuse_nonce:
            self.can_reuse_nonce = False
            return self.nonce
        else:
            return None

def _xor_bytes(a, b):
    assert len(a) == len(b)
    # FIXME is this an efficient thing to do, or should we store everything
    # that possibly needs xor'ing as long integers with an associated length?
    return bytes(_a ^ _b for (_a, _b) in zip(a, b))

class Algorithm(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def encrypt(cls, plaintext, aad, key, iv):
        """Return ciphertext + tag for given input data"""

    @abc.abstractmethod
    def decrypt(cls, ciphertext_and_tag, aad, key, iv):
        """Reverse encryption. Must raise ProtectionInvalid on any error
        stemming from untrusted data."""

class AES_CCM(Algorithm, metaclass=abc.ABCMeta):
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
    key_bytes = 16 # 128-bit key
    tag_bytes = 8 # 64-bit tag
    iv_bytes = 13 # 13-byte nonce

class AES_CCM_16_64_256(AES_CCM):
    # from RFC8152
    value = 11
    key_bytes = 32 # 256-bit key
    tag_bytes = 8 # 64-bit tag
    iv_bytes = 13 # 13-byte nonce

class AES_CCM_64_64_128(AES_CCM):
    # from RFC8152
    value = 12
    key_bytes = 16 # 128-bit key
    tag_bytes = 8 # 64-bit tag
    iv_bytes = 7 # 7-byte nonce

class AES_CCM_64_64_256(AES_CCM):
    # from RFC8152
    value = 13
    key_bytes = 32 # 256-bit key
    tag_bytes = 8 # 64-bit tag
    iv_bytes = 7 # 7-byte nonce

class AES_CCM_16_128_128(AES_CCM):
    # from RFC8152
    value = 30
    key_bytes = 16 # 128-bit key
    tag_bytes = 16 # 128-bit tag
    iv_bytes = 13 # 13-byte nonce

class AES_CCM_16_128_256(AES_CCM):
    # from RFC8152
    value = 31
    key_bytes = 32 # 256-bit key
    tag_bytes = 16 # 128-bit tag
    iv_bytes = 13 # 13-byte nonce

class AES_CCM_64_128_128(AES_CCM):
    # from RFC8152
    value = 32
    key_bytes = 16 # 128-bit key
    tag_bytes = 16 # 128-bit tag
    iv_bytes = 7 # 7-byte nonce

class AES_CCM_64_128_256(AES_CCM):
    # from RFC8152
    value = 33
    key_bytes = 32 # 256-bit key
    tag_bytes = 16 # 128-bit tag
    iv_bytes = 7 # 7-byte nonce


class AES_GCM(Algorithm, metaclass=abc.ABCMeta):
    """AES-GCM implemented using the Python cryptography library"""

    iv_bytes = 12 # 96 bits fixed size of the nonce

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
    key_bytes = 16 # 128-bit key
    tag_bytes = 16 # 128-bit tag

class A192GCM(AES_GCM):
    # from RFC8152
    value = 2
    key_bytes = 24 # 192-bit key
    tag_bytes = 16 # 128-bit tag

class A256GCM(AES_GCM):
    # from RFC8152
    value = 3
    key_bytes = 32 # 256-bit key
    tag_bytes = 16 # 128-bit tag

class ChaCha20Poly1305(Algorithm):
    # from RFC8152
    value = 24
    key_bytes = 32 # 256-bit key
    tag_bytes = 16 # 128-bit tag
    iv_bytes = 12 # 96-bit nonce

    @classmethod
    def encrypt(cls, plaintext, aad, key, iv):
        return aead.ChaCha20Poly1305(key).encrypt(iv, plaintext, aad)

    @classmethod
    def decrypt(cls, ciphertext_and_tag, aad, key, iv):
        try:
            return aead.ChaCha20Poly1305(key).decrypt(iv, ciphertext_and_tag, aad)
        except cryptography.exceptions.InvalidTag:
            raise ProtectionInvalid("Tag invalid")

algorithms = {
        'AES-CCM-16-64-128': AES_CCM_16_64_128(),
        'AES-CCM-16-64-256': AES_CCM_16_64_256(),
        'AES-CCM-64-64-128': AES_CCM_64_64_128(),
        'AES-CCM-64-64-256': AES_CCM_64_64_256(),
        'AES-CCM-16-128-128': AES_CCM_16_128_128(),
        'AES-CCM-16-128-256': AES_CCM_16_128_256(),
        'AES-CCM-64-128-128': AES_CCM_64_128_128(),
        'AES-CCM-64-128-256': AES_CCM_64_128_256(),
        'ChaCha20/Poly1305': ChaCha20Poly1305(),
        'A128GCM': A128GCM(),
        'A192GCM': A192GCM(),
        'A256GCM': A256GCM(),
        }

DEFAULT_ALGORITHM = 'AES-CCM-16-64-128'

_hash_backend = cryptography.hazmat.backends.default_backend()
hashfunctions = {
        'sha256': hashes.SHA256(),
        }

DEFAULT_HASHFUNCTION = 'sha256'

DEFAULT_WINDOWSIZE = 32

class SecurityContext(metaclass=abc.ABCMeta):
    # FIXME: define an interface for that

    # Indicates that in this context, when responding to a request, will always
    # be the *only* context that does. (This is primarily a reminder to stop
    # reusing nonces once multicast is implemented).
    is_unicast = True

    # Unless None, this is the value by which the running process recognizes
    # that the second phase of a B.1.2 replay window recovery Echo option comes
    # from the current process, and thus its sequence number is fresh
    echo_recovery = None

    # Authentication information carried with this security context; managed
    # externally by whatever creates the security context.
    authenticated_claims = []

    # message processing

    def _extract_external_aad(self, message, request_kid, request_piv):
        # If any option were actually Class I, it would be something like
        #
        # the_options = pick some of(message)
        # class_i_options = Message(the_options).opt.encode()

        oscore_version = 1
        class_i_options = b""

        external_aad = [
                oscore_version,
                [self.algorithm.value],
                request_kid,
                request_piv,
                class_i_options,
                ]

        external_aad = cbor.dumps(external_aad)

        return external_aad

    def _split_message(self, message):
        """Given a protected message, return the outer message that contains
        all Class I and Class U options (but without payload or Object-Security
        option), and a proto-inner message that contains all Class E options.

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

            outer_code = CHANGED

        # no max-age because these are always successsful responses
        outer_message = Message(code=outer_code,
                uri_host=outer_host,
                observe=None if message.code.is_response() else message.opt.observe,
                )
        if proxy_uri is not None:
            outer_message.set_request_uri(outer_uri)

        return outer_message, inner_message

    def _build_new_nonce(self):
        """This implements generation of a new nonce, assembled as per Figure 5
        of draft-ietf-core-object-security-06. Returns the shortened partial IV
        as well."""
        seqno = self.new_sequence_number()

        partial_iv = seqno.to_bytes(5, 'big')

        return (self._construct_nonce(partial_iv, self.sender_id), partial_iv.lstrip(b'\0') or b'\0')

    def _construct_nonce(self, partial_iv_short, piv_generator_id):
        pad_piv = b"\0" * (5 - len(partial_iv_short))

        s = bytes([len(piv_generator_id)])
        pad_id = b'\0' * (self.algorithm.iv_bytes - 6 - len(piv_generator_id))

        components = s + \
                pad_id + \
                piv_generator_id + \
                pad_piv + \
                partial_iv_short

        nonce = _xor_bytes(self.common_iv, components)

        return nonce

    @staticmethod
    def _compress(unprotected, protected):
        """Pack the untagged COSE_Encrypt0 object described by the arguments
        into two bytestrings suitable for the Object-Security option and the
        message body"""

        if protected:
            raise RuntimeError("Protection produced a message that has uncompressable fields.")

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

        if unprotected:
            raise RuntimeError("Protection produced a message that has uncompressable fields.")

        if firstbyte:
            return bytes([firstbyte]) + piv + s_kid_context + kid_data
        else:
            return b""

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

        assert (request_id is None) == message.code.is_request()

        outer_message, inner_message = self._split_message(message)

        protected = {}
        nonce = None
        unprotected = {}
        if request_id is not None:
            nonce = request_id.get_reusable_nonce()

        if nonce is None:
            nonce, partial_iv_short = self._build_new_nonce()

            unprotected[COSE_PIV] = partial_iv_short

        if message.code.is_request():
            unprotected[COSE_KID] = self.sender_id

            request_id = RequestIdentifiers(self.sender_id, partial_iv_short, nonce, can_reuse_nonce=None)

            if kid_context is True:
                if self.id_context is not None:
                    unprotected[COSE_KID_CONTEXT] = self.id_context
            elif kid_context is not False:
                unprotected[COSE_KID_CONTEXT] = kid_context

        assert protected == {}
        protected_serialized = b'' # were it into an empty dict, it'd be the cbor dump
        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(outer_message, request_id.kid, request_id.partial_iv)]
        aad = cbor.dumps(enc_structure)
        key = self.sender_key

        plaintext = bytes([inner_message.code]) + inner_message.opt.encode()
        if inner_message.payload:
            plaintext += bytes([0xFF])
            plaintext += inner_message.payload


        ciphertext_and_tag = self.algorithm.encrypt(plaintext, aad, key, nonce)

        option_data = self._compress(unprotected, protected)

        outer_message.opt.object_security = option_data
        outer_message.payload = ciphertext_and_tag

        # FIXME go through options section

        # the request_id in the second argument should be discarded by the
        # caller when protecting a response -- is that reason enough for an
        # `if` and returning None?
        return outer_message, request_id

    def unprotect(self, protected_message, request_id=None):
        assert (request_id is not None) == protected_message.code.is_response()
        is_response = protected_message.code.is_response()

        # Set to a raisable exception on replay check failures; it will be
        # raised, but the package may still be processed in the course of Echo handling.
        replay_error = None

        protected_serialized, protected, unprotected, ciphertext = self._extract_encrypted0(protected_message)

        if protected:
            raise ProtectionInvalid("The protected field is not empty")

        # FIXME check for duplicate keys in protected

        if unprotected.pop(COSE_KID, self.recipient_id) != self.recipient_id:
            # for most cases, this is caught by the session ID dispatch, but in
            # responses (where explicit sender IDs are atypical), this is a
            # valid check
            raise ProtectionInvalid("Sender ID does not match")

        if COSE_PIV not in unprotected:
            if not is_response:
                raise ProtectionInvalid("No sequence number provided in request")

            nonce = request_id.nonce
            seqno = None # sentinel for not striking out anyting
        else:
            partial_iv_short = unprotected[COSE_PIV]

            nonce = self._construct_nonce(partial_iv_short, self.recipient_id)

            seqno = int.from_bytes(partial_iv_short, 'big')

            if not is_response:
                if not self.recipient_replay_window.is_initialized():
                    replay_error = ReplayError("Sequence number check unavailable")
                elif not self.recipient_replay_window.is_valid(seqno):
                    replay_error = ReplayError("Sequence number was re-used")

                if replay_error is not None and self.echo_recovery is None:
                    # Don't even try decoding if there is no reason to
                    raise replay_error

                request_id = RequestIdentifiers(self.recipient_id, partial_iv_short, nonce, can_reuse_nonce=self.is_unicast and replay_error is None)

        # FIXME is it an error for additional data to be present in unprotected?

        if len(ciphertext) < self.algorithm.tag_bytes + 1: # +1 assures access to plaintext[0] (the code)
            raise ProtectionInvalid("Ciphertext too short")

        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(protected_message, request_id.kid, request_id.partial_iv)]
        aad = cbor.dumps(enc_structure)

        plaintext = self.algorithm.decrypt(ciphertext, aad, self.recipient_key, nonce)

        if not is_response and seqno is not None and replay_error is None:
            self.recipient_replay_window.strike_out(seqno)

        # FIXME add options from unprotected

        unprotected_message = Message(code=plaintext[0])
        unprotected_message.payload = unprotected_message.opt.decode(plaintext[1:])

        try_initialize = not self.recipient_replay_window.is_initialized() and \
                self.echo_recovery is not None
        if try_initialize:
            if protected_message.code.is_request():
                # Either accept into replay window and clear replay error, or raise
                # something that can turn into a 4.01,Echo response
                if unprotected_message.opt.echo == self.echo_recovery:
                    self.recipient_replay_window.initialize_from_freshlyseen(seqno)
                    replay_error = None
                else:
                    raise ReplayErrorWithEcho(secctx=self, request_id=request_id, echo=self.echo_recovery)
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

        return unprotected_message, request_id

    @staticmethod
    def _uncompress(option_data):
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
            unprotected[COSE_KID_CONTEXT] = tail[1:s+1]
            tail = tail[s+1:]

        if firstbyte & COMPRESSION_BIT_K:
            kid = tail
            unprotected[COSE_KID] = kid

        return b"", {}, unprotected

    @classmethod
    def _extract_encrypted0(cls, message):
        if message.opt.object_security is None:
            raise NotAProtectedMessage("No Object-Security option present", message)

        protected_serialized, protected, unprotected = cls._uncompress(message.opt.object_security)
        return protected_serialized, protected, unprotected, message.payload

    # context parameter setup

    def _kdf(self, master_salt, master_secret, role_id, out_type):
        out_bytes = {'Key': self.algorithm.key_bytes, 'IV': self.algorithm.iv_bytes}[out_type]

        info = cbor.dumps([
            role_id,
            self.id_context,
            self.algorithm.value,
            out_type,
            out_bytes
            ])
        hkdf = HKDF(
                algorithm=self.hashfun,
                length=out_bytes,
                salt=master_salt,
                info=info,
                backend=_hash_backend,
                )
        expanded = hkdf.derive(master_secret)
        return expanded

    def derive_keys(self, master_salt, master_secret):
        """Populate sender_key, recipient_key and common_iv from the algorithm,
        hash function and id_context already configured beforehand, and from
        the passed salt and secret."""

        self.sender_key = self._kdf(master_salt, master_secret, self.sender_id, 'Key')
        self.recipient_key = self._kdf(master_salt, master_secret, self.recipient_id, 'Key')

        self.common_iv = self._kdf(master_salt, master_secret, b"", 'IV')

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
        self._index = persisted['index']
        self._bitfield = persisted['bitfield']

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
            raise ValueError("Sequence number is not valid any more and "
                    "thus can't be removed from the window")
        overshoot = number - (self._index + self._size - 1)
        if overshoot > 0:
            self._index += overshoot
            self._bitfield >>= overshoot
        assert self.is_valid(number)
        self._bitfield |= 1 << (number - self._index)

        self.strike_out_callback()

    def persist(self):
        """Return a dict containing internal state which can be passed to init
        to recreated the replay window."""

        return {'index': self._index, 'bitfield': self._bitfield}

class FilesystemSecurityContext(SecurityContext):
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

    class LoadError(ValueError):
        """Exception raised with a descriptive message when trying to load a
        faulty security context"""

    def __init__(
            self,
            basedir,
            sequence_number_chunksize_start=10,
            sequence_number_chunksize_limit=10000,
            ):
        self.basedir = basedir

        self.lockfile = filelock.FileLock(os.path.join(basedir, 'lock'))
        # 0.001: Just fail if it can't be acquired
        # See https://github.com/benediktschmitt/py-filelock/issues/57
        try:
            self.lockfile.acquire(timeout=0.001)
        except:
            # No lock, no loading, no need to fail in __del__
            self.lockfile = None
            raise

        # Always enabled as committing to a file for every received request
        # would be a terrible burden.
        self.echo_recovery = secrets.token_bytes(8)

        try:
            self._load()
        except KeyError as k:
            raise self.LoadError("Configuration key missing: %s"%(k.args[0],))

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

            for (key, value) in filedata.items():
                if key.endswith('_hex'):
                    key = key[:-4]
                    value = binascii.unhexlify(value)
                elif key.endswith('_ascii'):
                    key = key[:-6]
                    value = value.encode('ascii')

                if key in data:
                    raise self.LoadError("Datum %r present in multiple input files at %r."%(key, self.basedir))

                data[key] = value

        self.algorithm = algorithms[data.get('algorithm', DEFAULT_ALGORITHM)]
        self.hashfun = hashfunctions[data.get('kdf-hashfun', DEFAULT_HASHFUNCTION)]

        windowsize = data.get('window', DEFAULT_WINDOWSIZE)
        if not isinstance(windowsize, int):
            raise self.LoadError("Non-integer replay window")

        self.sender_id = data['sender-id']
        self.recipient_id = data['recipient-id']

        if max(len(self.sender_id), len(self.recipient_id)) > self.algorithm.iv_bytes - 6:
            raise self.LoadError("Sender or Recipient ID too long (maximum length %s for this algorithm)" % (self.algorithm.iv_bytes - 6))

        master_secret = data['secret']
        master_salt = data.get('salt', b'')
        self.id_context = data.get('id-context', None)

        self.derive_keys(master_salt, master_secret)

        self.recipient_replay_window = ReplayWindow(windowsize, self._replay_window_changed)
        try:
            with open(os.path.join(self.basedir, 'sequence.json')) as f:
                sequence = json.load(f)
        except FileNotFoundError:
            self.sender_sequence_number = 0
            self.recipient_replay_window.initialize_empty()
            self.replay_window_persisted = True
        else:
            self.sender_sequence_number = int(sequence['next-to-send'])
            received = sequence['received']
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
                    raise self.LoadError("Persisted replay window state was not understood")
                self.replay_window_persisted = True

    # This is called internally whenever a new sequence number is taken or
    # crossed out from the window, and blocks a lot; B.1 mode mitigates that.
    #
    # Making it async and block in a threadpool would mitigate the blocking of
    # other messages, but the more visible effect of this will be that no
    # matter if sync or async, a reply will need to wait for a file sync
    # operation to conclude.
    def _store(self):
        tmphand, tmpnam = tempfile.mkstemp(dir=self.basedir,
                prefix='.sequence-', suffix='.json', text=True)

        data = {"next-to-send": self.sequence_number_persisted}
        if not self.replay_window_persisted:
            data['received'] = 'unknown'
        else:
            data['received'] = self.recipient_replay_window.persist()

        with os.fdopen(tmphand, 'w') as tmpfile:
            json.dump(data, tmpfile)
            tmpfile.flush()
            os.fsync(tmpfile.fileno())

        os.replace(tmpnam, os.path.join(self.basedir, 'sequence.json'))

    def _replay_window_changed(self):
        if self.replay_window_persisted:
            # Just remove the sequence numbers once from the file
            self.replay_window_persisted = False
            self._store()
        else:
            self._store()

    def post_seqnoincrease(self):
        if self.sender_sequence_number > self.sequence_number_persisted:
            self.sequence_number_persisted += self.sequence_number_chunksize

            self.sequence_number_chunksize = min(self.sequence_number_chunksize * 2, self.sequence_number_chunksize_limit)
            # FIXME: this blocks -- see https://github.com/chrysn/aiocoap/issues/178
            self._store()

            # The = case would only happen if someone deliberately sets all
            # numbers to 1 to force persisting on every step
            assert self.sender_sequence_number <= self.sequence_number_persisted

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

def verify_start(message):
    """Extract a sender ID and ID context (if present, otherwise None) from a
    message for the verifier to then pick a security context to actually verify
    the message.

    Call this only requests; for responses, you'll have to know the security
    context anyway, and there is usually no information to be gained."""

    _, _, unprotected, _ = SecurityContext._extract_encrypted0(message)

    try:
        # FIXME raise on duplicate key
        return unprotected[COSE_KID], unprotected.get(COSE_KID_CONTEXT, None)
    except KeyError:
        raise NotAProtectedMessage("No Sender ID present", message)

