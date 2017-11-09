# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains the tools to send OSCOAP secured messages.

(Work in progress.)"""

import hashlib
import json
import binascii
import os, os.path
import warnings
import tempfile
import abc

from aiocoap.message import Message
from aiocoap.util import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import cryptography.exceptions

import hkdf
import cbor

USE_COMPRESSION = True

class NotAProtectedMessage(ValueError):
    """Raised when verification is attempted on a non-OSCOAP message"""

    def __init__(self, message, plain_message):
        super().__init__(message)
        self.plain_message = plain_message

class ProtectionInvalid(ValueError):
    """Raised when verification of an OSCOAP message fails"""

class DecodeError(ProtectionInvalid):
    """Raised when verification of an OSCOAP message fails because CBOR or compressed data were erroneous"""

class ReplayError(ProtectionInvalid):
    """Raised when verification of an OSCOAP message fails because the sequence numbers was already used"""

def _xor_bytes(a, b):
    assert len(a) == len(b)
    # FIXME is this an efficient thing to do, or should we store everything
    # that possibly needs xor'ing as long integers with an associated length?
    return bytes(_a ^ _b for (_a, _b) in zip(a, b))

def _flip_first_bit(a):
    """Flip the first bit in a hex string"""
    return _xor_bytes(a, b"\x80" + b"\x00" * (len(a) - 1))

def _pad_iv(algorithm, short_partial):
    """Return the short_partial abbreviated version of a Partial IV and return
    the full Partial IV"""
    return b"\0" * (algorithm.iv_bytes - len(short_partial)) + short_partial

class Algorithm(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def encrypt(cls, plaintext, aad, key, iv):
        """Return (ciphertext, tag) for given input data"""

    @abc.abstractmethod
    def decrypt(cls, ciphertext, tag, aad, key, iv):
        """Reverse encryption. Must raise ProtectionInvalid on any error
        stemming from untrusted data."""

class AES_CCM(Algorithm, metaclass=abc.ABCMeta):
    """AES-CCM implemented using the Python cryptography library"""

    @classmethod
    def encrypt(cls, plaintext, aad, key, iv):
        joint = AESCCM(key, cls.tag_bytes).encrypt(iv, plaintext, aad)
        return joint[:len(plaintext)], joint[len(plaintext):]

    @classmethod
    def decrypt(cls, ciphertext, tag, aad, key, iv):
        try:
            return AESCCM(key, cls.tag_bytes).decrypt(iv, ciphertext + tag, aad)
        except cryptography.exceptions.InvalidTag:
            raise ProtectionInvalid("Tag invalid")

    max_seqno = property(lambda self: 2**(min(8 * self.iv_bytes, 56) - 1) - 1)

class AES_CCM_64_64_128(AES_CCM):
    # from draft-ietf-cose-msg-24 and draft-ietf-core-object-security 3.2.1
    value = 12
    key_bytes = 16 # 128 bit, the 'k' column
    iv_bytes = 7 # 56 bit nonce. Implies the 64bit (8 bytes = 15 - 7) in the 'L' column
    tag_bytes = 8 # 64 bit tag, the 'M' column

algorithms = {
        'AES-CCM-64-64-128': AES_CCM_64_64_128(),
        }

hashfunctions = {
        'sha256': hashlib.sha256,
        }

class SecurityContext:
    # FIXME: protcol

    # message processing

    def _extract_external_aad(self, message, request_kid, request_seq):
        # If any option were actually Class I, it would be something like
        #
        # class_i_options = Message(observe=message.opt.observe).opt.encode()
        #
        # (but Observe is in proper Class I neither in requests nor in
        # responses)

        class_i_options = b""

        external_aad = [
                1, # ver
                message.code,
                class_i_options,
                self.algorithm.value,
                request_kid,
                request_seq
                ]

        external_aad = cbor.dumps(external_aad)

        return external_aad

    def _split_message(self, message):
        """Given a protected message, return the outer message that contains
        all Class I and Class U options (but without payload or Object-Security
        option), and a proto-inner message that contains all Class E options."""


        # not trying to preserve token or mid, they're up to the transport
        outer_message = Message(code=message.code)
        inner_message = message.copy()

        if inner_message.code.is_request():
            protected_uri = inner_message.get_request_uri()

            if protected_uri.count('/') >= 3:
                protected_uri = protected_uri[:protected_uri.index('/', protected_uri.index('/', protected_uri.index('/') + 1) + 1)]
            outer_message.set_request_uri(protected_uri)

            if inner_message.opt.proxy_uri:
                # pack them into the separatable fields ... hopefully (FIXME
                # use a set_request_uri that *never* uses Proxy-Uri)
                inner_message.set_request_uri(protected_uri)

            inner_message.opt.uri_host = None
            inner_message.opt.uri_port = None
            inner_message.opt.proxy_uri = None
            inner_message.opt.proxy_scheme = None

        outer_message.opt.observe = inner_message.opt.observe
        if inner_message.code.is_response():
            inner_message.opt.observe = None

        return outer_message, inner_message

    def protect(self, message, request_data=None, *, can_use_bitflip=True):
        assert (request_data is None) == message.code.is_request()
        if request_data is not None:
            request_kid, request_partiv = request_data

        outer_message, inner_message = self._split_message(message)

        if request_data is None or not can_use_bitflip:
            seqno = self.new_sequence_number()

            partial_iv = seqno.to_bytes(self.algorithm.iv_bytes, 'big')
            partial_iv_short = partial_iv.lstrip(b'\0')
            iv = _xor_bytes(self.sender_iv, partial_iv)

            unprotected = {
                    6: partial_iv_short,
                    }
            if request_data is None:
                # this is usually the case; the exception is observe
                unprotected[4] = self.sender_id

                request_kid = self.sender_id
                request_partiv = partial_iv_short
        else:
            partial_iv = _pad_iv(self.algorithm, request_partiv)
            iv = _flip_first_bit(_xor_bytes(partial_iv, self.sender_iv))
            unprotected = {}

        protected = {}

        assert protected == {}
        protected_serialized = b'' # were it into an empty dict, it'd be the cbor dump
        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(outer_message, request_kid, request_partiv)]
        aad = cbor.dumps(enc_structure)
        key = self.sender_key

        plaintext = inner_message.opt.encode()
        if inner_message.payload:
            plaintext += bytes([0xFF])
            plaintext += inner_message.payload


        ciphertext, tag = self.algorithm.encrypt(plaintext, aad, key, iv)

        if USE_COMPRESSION:
            if protected:
                raise RuntimeError("Protection produced a message that has uncompressable fields.")

            if set(unprotected.keys()) - {4, 6}:
                raise RuntimeError("Protection produced a message that has uncompressable fields.")
            else:
                if 6 in unprotected:
                    # or b"\0": FIXME is this explicit in the spec? this works
                    # around the piv being treated as absent when decoded.
                    piv = unprotected[6] or b"\0"
                    if len(piv) > 0b111:
                        raise ValueError("Can't encode overly long partial IV")
                else:
                    piv = b""
                firstbyte = len(piv)
                if 4 in unprotected:
                    firstbyte |= 0b1000
                    kid_data = bytes([len(unprotected[4])]) + unprotected[4]
                else:
                    kid_data = b""

                oscoap_data = bytes([firstbyte]) + piv + kid_data + ciphertext + tag
        else:
            cose_encrypt0 = [protected_serialized, unprotected, ciphertext + tag]
            oscoap_data = cbor.dumps(cose_encrypt0)

        if inner_message.code.can_have_payload():
            outer_message.opt.object_security = b''
            outer_message.payload = oscoap_data
        else:
            outer_message.opt.object_security = oscoap_data

        # FIXME go through options section
        return outer_message, (request_kid, request_partiv)

    def unprotect(self, protected_message, request_data=None):
        assert (request_data is not None) == protected_message.code.is_response()
        if request_data is not None:
            request_kid, request_partiv = request_data

        protected_serialized, protected, unprotected, ciphertext = self._extract_encrypted0(protected_message, is_request=request_data is None)

        if protected:
            raise ProtectionInvalid("The protected field is not empty")

        # FIXME check for duplicate keys in protected

        if unprotected.pop(4, self.recipient_id) != self.recipient_id:
            # for most cases, this is caught by the session ID dispatch, but in
            # responses (where explicit sender IDs are atypical), this is a
            # valid check
            raise ProtectionInvalid("Sender ID does not match")

        if 6 not in unprotected:
            if request_data is None:
                raise ProtectonInvalid("No sequence number provided in request")
            partial_iv = _pad_iv(self.algorithm, request_partiv)
            iv = _flip_first_bit(_xor_bytes(partial_iv, self.recipient_iv))
            seqno = None # sentinel for not striking out anyting
        else:
            partial_iv_short = unprotected[6]

            if request_data is None:
                request_partiv = partial_iv_short
                request_kid = self.recipient_id

            seqno = int.from_bytes(partial_iv_short, 'big')

            if not self.recipient_replay_window.is_valid(seqno):
                raise ReplayError("Sequence number was re-used")

            partial_iv = _pad_iv(self.algorithm, partial_iv_short)
            iv = _xor_bytes(self.recipient_iv, partial_iv)

        # FIXME is it an error for additional data to be present in unprotected?

        if len(ciphertext) < self.algorithm.tag_bytes:
            raise ProtectionInvalid("Ciphertext shorter than tag length")

        tag = ciphertext[-self.algorithm.tag_bytes:]
        ciphertext = ciphertext[:-self.algorithm.tag_bytes]

        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(protected_message, request_kid, request_partiv)]
        aad = cbor.dumps(enc_structure)

        plaintext = self.algorithm.decrypt(ciphertext, tag, aad, self.recipient_key, iv)

        if seqno is not None:
            self.recipient_replay_window.strike_out(seqno)

        # FIXME add options from unprotected

        unprotected_message = Message(code=protected_message.code)
        unprotected_message.payload = unprotected_message.opt.decode(plaintext)

        if unprotected_message.code.is_request:
            unprotected_message.opt.observe = protected_message.opt.observe
        else:
            if protected_message.opt.observe is not None:
                # is it really be as easy as that?
                unprotected_message.opt.observe = seqno

        return unprotected_message, (request_kid, request_partiv)

    @classmethod
    def _extract_encrypted0(cls, message, is_request):
        if message.opt.object_security is None:
            raise NotAProtectedMessage("No Object-Security option present", message)

        # FIXME it's an error to have this in the wrong place
        serialized = message.opt.object_security or message.payload

        if USE_COMPRESSION:
            if not serialized:
                raise DecodeError("Protected data too short for uncompression")

            if serialized[0] & 0b11110000:
                raise DecodeError("Protected data uses reserved fields")

            unprotected = {}

            k = (serialized[0] >> 3) & 1
            pivsz = serialized[0] & 0b111
            if pivsz:
                unprotected[6] = serialized[1:1 + pivsz]
            tail = serialized[1 + pivsz:]
            if k:
                if not tail:
                    raise DecodeError("Protected data too short for kid uncompression")
                unprotected[4] = tail[1:1 + tail[0]]
                tail = tail[1 + tail[0]:]

            return b"", {}, unprotected, tail
        else:
            try:
                encrypted0 = cbor.loads(serialized)
            except ValueError:
                raise DecodeError("Error parsing the CBOR payload")

            if not isinstance(encrypted0, list) or len(encrypted0) != 3:
                raise DecodeError("CBOR payload is not structured like Encrypt0")

            try:
                protected = cbor.loads(encrypted0[0])
            except ValueError:
                raise DecodeError("Error parsing the CBOR protected data")

            return encrypted0[0], protected, encrypted0[1], encrypted0[2]

    # sequence number handling

    def new_sequence_number(self):
        retval = self.sender_sequence_number
        if retval > self.algorithm.max_seqno:
            raise ValueError("Sequence number too large, context is exhausted.")
        self.sender_sequence_number += 1
        # FIXME maybe _store now?
        return retval

class ReplayWindow:
    # FIXME: protcol, abc
    pass

class SimpleReplayWindow(ReplayWindow):
    """A ReplayWindow that keeps its seen sequence numbers in a sorted list;
    all entries of the list and all numbers smaller than the first entry are
    considered seen.

    This is not very efficient, but easy to understand and to serialize.

    >>> w = SimpleReplayWindow()
    >>> w.strike_out(5)
    >>> w.is_valid(3)
    True
    >>> w.is_valid(5)
    False
    >>> w.strike_out(0)
    >>> print(w.seen)
    [0, 5]
    >>> w.strike_out(1)
    >>> w.strike_out(2)
    >>> print(w.seen)
    [2, 5]
    >>> w.is_valid(1)
    False
    """
    window_count = 64 # not a window size: window size would be size of a bit field, while this is the size of the ones

    def __init__(self, seen=None):
        if not seen: # including empty-list case
            self.seen = [-1]
        else:
            self.seen = sorted(seen)

    def is_valid(self, number):
        if number < self.seen[0]:
            return False
        return number not in self.seen

    def strike_out(self, number):
        if not self.is_valid(number):
            raise ValueError("Sequence number is not valid any more and "
                    "thus can't be removed from the window")
        for i, n in enumerate(self.seen):
            if n > number:
                break
        else:
            i = i + 1
        self.seen.insert(i, number)
        assert self.seen == sorted(self.seen)
        # cleanup
        while len(self.seen) > 1 and (
                len(self.seen) > self.window_count or
                self.seen[0] + 1 == self.seen[1]
                ):
            self.seen.pop(0)

class FilesystemSecurityContext(SecurityContext):
    """Security context stored in a directory as distinct files containing
    containing

    * Master secret, master salt, the sender IDs of the participants, and
      optionally algorithm, the KDF hash function, and replay window size
      (settings.json and secrets.json, where the latter is typically readable
      only for the user)
    * sequence numbers and replay windows (sequence.json, the only file the
      process needs write access to)

    The static parameters can all either be placed in settings.json or
    secrets.json, but must not be present in both; the presence of either file
    is sufficient.

    The static files are phrased in a way that allows using the same files for
    server and client; only by passing "client" or "server" as role parameter
    at load time, the IDs are are assigned to the context as sender or
    recipient ID. (The sequence number file is set up in a similar way in
    preparation for multicast operation; but is not yet usable from a directory
    shared between server and client; when multicast is actually explored, the
    sequence file might be renamed to contain the sender ID for shared use of a
    directory).

    Note that the sequence number file is updated in an atomic fashion which
    requires file creation privileges in the directory. If privilege separation
    between settings/key changes and sequence number changes is desired, one
    way to achieve that on Linux is giving the aiocoap process's user group
    write permissions on the directory and setting the sticky bit on the
    directory, thus forbidding the user to remove the settings/secret files not
    owned by him.
    """
    def __init__(self, basedir, role):
        self.basedir = basedir
        self._load(role)

    def _load(self, my_role):
        data = {}
        for readfile in ("secret.json", "settings.json"):
            try:
                filedata = json.load(open(os.path.join(self.basedir, readfile)))
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
                    raise ValueError("Datum %r present in multiple input files at %r."%(key, self.basedir))

                data[key] = value

        self.algorithm = algorithms[data.get('algorithm', 'AES-CCM-64-64-128')]
        self.hashfun = hashfunctions[data.get('kdf-hashfun', 'sha256')]

        sender_id = data.get('sender-id', b'\x00')
        recipient_id = data.get('recipient-id', b'\x01')
        if my_role == 'server':
            self.sender_id = data['server-sender-id']
            self.recipient_id = data['client-sender-id']
        elif my_role == 'client':
            self.sender_id = data['client-sender-id']
            self.recipient_id = data['server-sender-id']
        else:
            raise ValueError("Unknown role")

        master_secret = data['secret']
        master_salt = data.get('salt', b'')

        self.sender_key = self._kdf(master_secret, master_salt, self.sender_id, 'Key')
        self.sender_iv = self._kdf(master_secret, master_salt, self.sender_id, 'IV')
        self.recipient_key = self._kdf(master_secret, master_salt, self.recipient_id, 'Key')
        self.recipient_iv = self._kdf(master_secret, master_salt, self.recipient_id, 'IV')

        try:
            sequence = json.load(open(os.path.join(self.basedir, 'sequence.json')))
        except FileNotFoundError:
            self.sender_sequence_number = 0
            self.recipient_replay_window = SimpleReplayWindow([])
        else:
            sender_hex = binascii.hexlify(self.sender_id).decode('ascii')
            recipient_hex = binascii.hexlify(self.recipient_id).decode('ascii')
            self.sender_sequence_number = int(sequence['used'][sender_hex])
            self.recipient_replay_window = SimpleReplayWindow([int(x) for x in
                sequence['seen'][recipient_hex]])
            if len(sequence['used']) != 1 or len(sequence['seen']) != 1:
                warnings.warn("Sequence files shared between roles are "
                        "currently not supported.")

    def _kdf(self, master_secret, master_salt, role_id, out_type):
        out_bytes = {'Key': self.algorithm.key_bytes, 'IV': self.algorithm.iv_bytes}[out_type]

        info = cbor.dumps([
            role_id,
            self.algorithm.value,
            out_type,
            out_bytes
            ])
        extracted = hkdf.hkdf_extract(master_salt, master_secret, hash=self.hashfun)
        expanded = hkdf.hkdf_expand(extracted, info=info, hash=self.hashfun,
                length=out_bytes)
        return expanded

    # FIXME when/how will this be called?
    #
    # it might be practical to make sender_sequence_number and recipient_replay_window
    # properties private, and provide access to them in a way that triggers
    # store or at least a delayed store.
    def _store(self):
        tmphand, tmpnam = tempfile.mkstemp(dir=self.basedir,
                prefix='.sequence-', suffix='.json', text=True)

        sender_hex = binascii.hexlify(self.sender_id).decode('ascii')
        recipient_hex = binascii.hexlify(self.recipient_id).decode('ascii')

        with os.fdopen(tmphand, 'w') as tmpfile:
            tmpfile.write('{\n'
                '  "used": {"%s": %d},\n'
                '  "seen": {"%s": %s}\n}'%(
                sender_hex, self.sender_sequence_number,
                recipient_hex, self.recipient_replay_window.seen))

        os.rename(tmpnam, os.path.join(self.basedir, 'sequence.json'))

    @classmethod
    def generate(cls, basedir):
        """Create a security context directory from default parameters and a
        random key; it is an error if that directory already exists.

        No SecurityContext object is returned immediately, as it is expected
        that the generated context can't be used immediately but first needs to
        be copied to another party and then can be opened in either the sender
        or the recipient role."""
        # shorter would probably be OK too (that token might be suitable to
        # even skip extraction), but for the purpose of generating conformant
        # example contexts.
        master_secret = secrets.token_bytes(nbytes=32)

        os.makedirs(basedir)
        with open(os.path.join(basedir, 'settings.json'), 'w') as settingsfile:
            settingsfile.write("{\n"
                    '  "sender-id_hex": "00",\n'
                    '  "recipient-id_hex": "01",\n'
                    '  "algorithm": "AES-CCM-64-64-128",\n'
                    '  "kdf-hashfun": "sha256"\n'
                    '}')

        # atomicity is not really required as this is a new directory, but the
        # readable-by-us-only property is easily achieved with mkstemp
        tmphand, tmpnam = tempfile.mkstemp(dir=basedir, prefix='.secret-',
                suffix='.json', text=True)
        with os.fdopen(tmphand, 'w') as secretfile:
            secretfile.write("{\n"
                    '  "secret_hex": "%s"\n'
                    '}'%binascii.hexlify(master_secret).decode('ascii'))
        os.rename(tmpnam, os.path.join(basedir, 'secret.json'))

def verify_start(message):
    """Extract a CID from a message for the verifier to then pick a security
    context to actually verify the message.

    Call this only requests; for responses, you'll have to know the security
    context anyway, and there is usually no information to be gained (and
    things would even fail completely in compressed messages)."""

    _, _, unprotected, _ = SecurityContext._extract_encrypted0(message, is_request=True)

    try:
        # FIXME raise on duplicate key
        return unprotected[4]
    except KeyError:
        raise NotAProtectedMessage("No CID present", message)

