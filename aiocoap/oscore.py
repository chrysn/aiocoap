# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains the tools to send OSCORE secured messages.

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
from aiocoap.numbers import POST, FETCH, CHANGED, CONTENT

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import cryptography.exceptions

import hkdf
import cbor

USE_COMPRESSION = True
MAX_SEQNO = 2**40 - 1

class NotAProtectedMessage(ValueError):
    """Raised when verification is attempted on a non-OSCORE message"""

    def __init__(self, message, plain_message):
        super().__init__(message)
        self.plain_message = plain_message

class ProtectionInvalid(ValueError):
    """Raised when verification of an OSCORE message fails"""

class DecodeError(ProtectionInvalid):
    """Raised when verification of an OSCORE message fails because CBOR or compressed data were erroneous"""

class ReplayError(ProtectionInvalid):
    """Raised when verification of an OSCORE message fails because the sequence numbers was already used"""

def _xor_bytes(a, b):
    assert len(a) == len(b)
    # FIXME is this an efficient thing to do, or should we store everything
    # that possibly needs xor'ing as long integers with an associated length?
    return bytes(_a ^ _b for (_a, _b) in zip(a, b))

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

class AES_CCM_64_64_128(AES_CCM):
    # from RFC8152 and draft-ietf-core-object-security-0[012] 3.2.1
    value = 12
    key_bytes = 16 # 128 bit, the 'k' column
    iv_bytes = 7 # 56 bit nonce. Implies the 64bit (8 bytes = 15 - 7) in the 'L' column
    tag_bytes = 8 # 64 bit tag, the 'M' column

class AES_CCM_16_64_128(AES_CCM):
    # from RFC8152
    value = 10
    key_bytes = 16 # 128 bit, the 'k' column
    iv_bytes = 13 # from L=16 column: 15 - L/8 = 13, and the description
    tag_bytes = 8 # 64 bit tag, the 'M' column

algorithms = {
        'AES-CCM-16-64-128': AES_CCM_16_64_128(),
        'AES-CCM-64-64-128': AES_CCM_64_64_128(),
        }

hashfunctions = {
        'sha256': hashlib.sha256,
        }

class SecurityContext:
    # FIXME: define an interface for that

    # message processing

    def _extract_external_aad(self, message, request_kid, request_piv):
        # If any option were actually Class I, it would be something like
        #
        # class_i_options = Message(the_options).opt.encode()

        version = 1
        class_i_options = b""

        external_aad = [
                version,
                self.algorithm.value,
                request_kid,
                request_piv,
                class_i_options,
                ]

        external_aad = cbor.dumps(external_aad)

        return external_aad

    def _split_message(self, message):
        """Given a protected message, return the outer message that contains
        all Class I and Class U options (but without payload or Object-Security
        option), and a proto-inner message that contains all Class E options."""

        inner_message = message.copy()

        if message.code.is_request():
            outer_uri = message.get_request_uri()

            if outer_uri.count('/') >= 3:
                outer_uri = outer_uri[:outer_uri.index('/', outer_uri.index('/', outer_uri.index('/') + 1) + 1)]

            inner_message = message.copy(
                    # explicitly passing the .uri so that it gets split up;
                    # FIXME make sure it always is, even in exotic schemes
                    uri=message.get_request_uri(),
                    uri_host=None,
                    uri_port=None,
                    proxy_uri=None,
                    proxy_scheme=None,
                    )

            if message.opt.observe is None:
                outer_code = POST
            else:
                outer_code = FETCH
        else:
            outer_uri = None

            inner_message = message.copy()

            if message.opt.observe is None:
                outer_code = CHANGED
            else:
                outer_code = CONTENT

        outer_message = Message(code=outer_code, uri=outer_uri,
                observe=None if message.code.is_response() else message.opt.observe,
                max_age=0 if message.code.is_response() and message.opt.observe is not None else None,
                )

        return outer_message, inner_message

    def _build_new_nonce(self):
        """This implements generation of a new nonce, assembled as per Figure 5
        of draft-ietf-core-object-security-06. Returns the shortened partial IV
        as well."""
        seqno = self.new_sequence_number()

        partial_iv = seqno.to_bytes(5, 'big')

        return (self._construct_nonce(partial_iv, self.sender_id), partial_iv.lstrip(b'\0')) or b'\0'

    def _construct_nonce(self, partial_iv_short, piv_generator_id):
        partial_iv = b"\0" * (5 - len(partial_iv_short)) + partial_iv_short

        s = bytes([len(piv_generator_id)])
        pad = b'\0' * (self.algorithm.iv_bytes - 6 - len(piv_generator_id))

        components = s + \
                pad + \
                piv_generator_id + \
                partial_iv

        nonce = _xor_bytes(self.common_iv, components)

        return nonce

    @staticmethod
    def _compress(unprotected, protected):
        """Pack the untagged COSE_Encrypt0 object described by the arguments
        into two bytestrings suitable for the Object-Security option and the
        message body"""

        if protected:
            raise RuntimeError("Protection produced a message that has uncompressable fields.")

        if set(unprotected.keys()) - {4, 6}:
            raise RuntimeError("Protection produced a message that has uncompressable fields.")

        if 6 in unprotected:
            piv = unprotected[6] or b""
            if len(piv) > 0b111:
                raise ValueError("Can't encode overly long partial IV")
        else:
            piv = b""

        firstbyte = len(piv)
        if 4 in unprotected:
            firstbyte |= 0b1000
            kid_data = unprotected[4]
        else:
            kid_data = b""

        if firstbyte:
            return bytes([firstbyte]) + piv + kid_data
        else:
            return b""

    def protect(self, message, request_data=None, *, can_reuse_partiv=True):
        assert (request_data is None) == message.code.is_request()
        if request_data is not None:
            request_kid, request_partiv, request_nonce = request_data

        outer_message, inner_message = self._split_message(message)

        if request_data is None or not can_reuse_partiv or message.opt.observe is not None:
            nonce, partial_iv_short = self._build_new_nonce()

            unprotected = {
                    6: partial_iv_short,
                    }
            if request_data is None:
                # this is usually the case; the exception is observe
                unprotected[4] = self.sender_id

                request_kid = self.sender_id
                request_partiv = partial_iv_short
                request_nonce = nonce
        else:
            nonce = request_nonce
            unprotected = {}

        protected = {}

        assert protected == {}
        protected_serialized = b'' # were it into an empty dict, it'd be the cbor dump
        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(outer_message, request_kid, request_partiv)]
        aad = cbor.dumps(enc_structure)
        key = self.sender_key

        plaintext = bytes([inner_message.code]) + inner_message.opt.encode()
        if inner_message.payload:
            plaintext += bytes([0xFF])
            plaintext += inner_message.payload


        ciphertext, tag = self.algorithm.encrypt(plaintext, aad, key, nonce)

        option_data = self._compress(unprotected, protected)

        outer_message.opt.object_security = option_data
        outer_message.payload = ciphertext + tag

        # FIXME go through options section

        # the request_data in the second argument should be discarded by the
        # caller when protecting a response -- is that reason enough for an
        # `if` and returning None?
        return outer_message, (request_kid, request_partiv, request_nonce)

    def unprotect(self, protected_message, request_data=None):
        assert (request_data is not None) == protected_message.code.is_response()
        if request_data is not None:
            request_kid, request_partiv, request_nonce = request_data

        protected_serialized, protected, unprotected, ciphertext = self._extract_encrypted0(protected_message)

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

            nonce = request_nonce
            seqno = None # sentinel for not striking out anyting
        else:
            partial_iv_short = unprotected[6]

            seqno = int.from_bytes(partial_iv_short, 'big')

            if not self.recipient_replay_window.is_valid(seqno):
                raise ReplayError("Sequence number was re-used")

            nonce = self._construct_nonce(partial_iv_short, self.recipient_id)

            if request_data is None: # ie. we're unprotecting a request
                request_partiv = partial_iv_short
                request_kid = self.recipient_id
                request_nonce = nonce

        # FIXME is it an error for additional data to be present in unprotected?

        if len(ciphertext) < self.algorithm.tag_bytes + 1: # +1 assures access to plaintext[0]
            raise ProtectionInvalid("Ciphertext too short")

        tag = ciphertext[-self.algorithm.tag_bytes:]
        ciphertext = ciphertext[:-self.algorithm.tag_bytes]

        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(protected_message, request_kid, request_partiv)]
        aad = cbor.dumps(enc_structure)

        plaintext = self.algorithm.decrypt(ciphertext, tag, aad, self.recipient_key, nonce)

        if seqno is not None:
            self.recipient_replay_window.strike_out(seqno)

        # FIXME add options from unprotected

        unprotected_message = Message(code=plaintext[0])
        unprotected_message.payload = unprotected_message.opt.decode(plaintext[1:])

        if unprotected_message.code.is_request():
            unprotected_message.opt.observe = protected_message.opt.observe
        else:
            if protected_message.opt.observe is not None:
                unprotected_message.opt.observe = seqno

        return unprotected_message, (request_kid, request_partiv, request_nonce)

    @staticmethod
    def _uncompress(option_data):
        if option_data == b"":
            firstbyte = 0
        else:
            firstbyte = option_data[0]
            tail = option_data[1:]

        unprotected = {}

        if firstbyte & 0b11100000:
            raise DecodeError("Protected data uses reserved fields")

        pivsz = firstbyte & 0b111
        if pivsz:
            if len(tail) < pivsz:
                raise DecodeError("Partial IV announced but not present")
            unprotected[6] = tail[:pivsz]
            tail = tail[pivsz:]

        if firstbyte & 0b00010000:
            # context hint
            s = tail[0]
            if len(tail) - 1 < s:
                raise DecodeError("Context hint announced but not present")
            # discarded, see @@@
            context_hint = tail[1:s+1]
            tail = tail[s+1:]

        if firstbyte & 0b00001000:
            kid = tail
            unprotected[4] = tail

        return b"", {}, unprotected

    @classmethod
    def _extract_encrypted0(cls, message):
        if message.opt.object_security is None:
            raise NotAProtectedMessage("No Object-Security option present", message)

        protected_serialized, protected, unprotected = cls._uncompress(message.opt.object_security)
        return protected_serialized, protected, unprotected, message.payload

    # sequence number handling

    def new_sequence_number(self):
        retval = self.sender_sequence_number
        if retval >= MAX_SEQNO:
            raise ValueError("Sequence number too large, context is exhausted.")
        self.sender_sequence_number += 1
        # FIXME maybe _store now?
        return retval

class ReplayWindow:
    # FIXME: interface, abc
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

    class LoadError(ValueError):
        """Exception raised with a descriptive message when trying to load a
        faulty security context"""

    def __init__(self, basedir, role):
        self.basedir = basedir
        try:
            self._load(role)
        except KeyError as k:
            raise self.LoadError("Configuration key missing: %s"%(k.args[0],))

    def _load(self, my_role):
        # doesn't check for KeyError on every occasion, relies on __init__ to
        # catch that

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
                    raise self.LoadError("Datum %r present in multiple input files at %r."%(key, self.basedir))

                data[key] = value

        self.algorithm = algorithms[data.get('algorithm', 'AES-CCM-64-64-128')]
        self.hashfun = hashfunctions[data.get('kdf-hashfun', 'sha256')]

        if my_role == 'server':
            self.sender_id = data['server-sender-id']
            self.recipient_id = data['client-sender-id']
        elif my_role == 'client':
            self.sender_id = data['client-sender-id']
            self.recipient_id = data['server-sender-id']
        else:
            raise self.LoadError("Unknown role")

        if max(len(self.sender_id), len(self.recipient_id)) > self.algorithm.iv_bytes - 6:
            raise self.LoadError("Sender or Recipient ID too long (maximum length %s for this algorithm)" % (self.algorithm.iv_bytes - 6))

        master_secret = data['secret']
        master_salt = data.get('salt', b'')

        self.sender_key = self._kdf(master_salt, master_secret, self.sender_id, 'Key')
        self.recipient_key = self._kdf(master_salt, master_secret, self.recipient_id, 'Key')

        self.common_iv = self._kdf(master_salt, master_secret, None, 'IV')

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

    def _kdf(self, master_salt, master_secret, role_id, out_type):
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
                    '  "server-id_hex": "00",\n'
                    '  "client-id_hex": "01",\n'
                    '  "algorithm": "AES-CCM-16-64-128",\n'
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

    _, _, unprotected, _ = SecurityContext._extract_encrypted0(message)

    try:
        # FIXME raise on duplicate key
        return unprotected[4]
    except KeyError:
        raise NotAProtectedMessage("No Sender ID present", message)

