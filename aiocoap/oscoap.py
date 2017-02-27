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
from aiocoap import numbers
from aiocoap.util import secrets
import aiocoap.util.crypto

import hkdf
import cbor

class NotAProtectedMessage(ValueError):
    """Raised when verification is attempted on a non-OSCOAP message"""

class ProtectionInvalid(ValueError):
    """Raised when verification of an OSCOAP message fails"""

def _xor_bytes(a, b):
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
    @classmethod
    def encrypt(cls, plaintext, aad, key, iv):
        return aiocoap.util.crypto.encrypt_ccm(plaintext, aad, key, iv, cls.tag_bytes)

    @classmethod
    def decrypt(cls, ciphertext, tag, aad, key, iv):
        if len(tag) != cls.tag_bytes:
            # this would be caught by the backend too, but i prefer not to pass
            # untrusted information to the crypto library where it might not
            # expect it to be untrusted
            raise ProtectionInvalid("Unsuitable tag length for algorithm")
        try:
            return aiocoap.util.crypto.decrypt_ccm(ciphertext, aad, tag, key, iv)
        except aiocoap.util.crypto.InvalidAEAD:
            raise ProtectionInvalid

    max_seqno = property(lambda self: 2**(8 * self.iv_bytes) - 1)

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

    def _extract_external_aad(self, message, i_am_sender, request_partiv=None):
        external_aad = [
                1, # ver
                message.code,
                self.algorithm.value,
                ]
        if message.code.is_request():
            external_aad.extend([
                # FIXME blockwise
                ])
        else:
            external_aad.extend([
                self.cid,
                self.other_id if i_am_sender else self.my_id,
                request_partiv
                # FIXME blockwise
                ])

        external_aad = cbor.dumps(external_aad)

        return external_aad

    def protect(self, message, request_partiv=None):
        # not trying to preserve token or mid, they're up to the transport
        outer_message = Message(code=message.code)
        if message.code.is_request():
            protected_uri = message.get_request_uri()
            if protected_uri.count('/') >= 3:
                protected_uri = protected_uri[:protected_uri.index('/', protected_uri.index('/', protected_uri.index('/') + 1) + 1)]
            outer_message.set_request_uri(protected_uri)

        # FIXME any options to move out?
        inner_message = message

        seqno = self.new_sequence_number()
        partial_iv = binascii.unhexlify("%014x"%seqno)
        iv = _xor_bytes(self.my_iv, partial_iv)

        protected = {
                6: partial_iv.lstrip(b'\0'),
                }
        if inner_message.code.is_request():
            protected[4] = self.cid # the kid

        unprotected = {}

        # FIXME verify that cbor.dumps follows cose-msg-24 section 14
        protected_serialized = cbor.dumps(protected)
        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(outer_message, True, request_partiv)]
        aad = cbor.dumps(enc_structure)
        key = self.my_key

        plaintext = inner_message.opt.encode()
        if inner_message.payload:
            plaintext += bytes([0xFF])
            plaintext += inner_message.payload


        ciphertext, tag = self.algorithm.encrypt(plaintext, aad, key, iv)

        cose_encrypt0 = [protected_serialized, unprotected, ciphertext + tag]
        oscoap_data = cbor.dumps(cose_encrypt0)

        if inner_message.code.can_have_payload():
            outer_message.opt.object_security = b''
            outer_message.payload = oscoap_data
            outer_message.opt.content_format = numbers.media_types_rev['application/oscon']
        else:
            outer_message.opt.object_security = oscoap_data

        # FIXME go through options section
        return outer_message, protected[6]

    def unprotect(self, protected_message, request_partiv=None):
        protected_serialized, protected, unprotected, ciphertext = self._extract_encrypted0(protected_message)

        if unprotected:
            raise ProtectionInvalid("The unprotected field is not empty")

        # FIXME check for duplicate keys
        try:
            hexlified = binascii.hexlify(protected[6])
            seqno = int(hexlified, 16) if hexlified else 0
        except (TypeError, KeyError):
            raise ProtectionInvalid("No serial number provided")

        if request_partiv is None:
            if protected.get(4, None) != self.cid:
                raise ProtectionInvalid("Protected CID does not match")
        else:
            # FIXME: is it ok to be present, and if yes, do i need to check it?
            if 4 in protected:
                raise ProtectionInvalid("CID in response")

        # FIXME is it an error for additional data to be present?

        # FIXME check sid if present

        if len(ciphertext) < self.algorithm.tag_bytes:
            raise ProtectionInvalid("Ciphertext shorter than tag length")

        try:
            self.other_replay_window.strike_out(seqno)
        except ValueError:
            raise ProtectionInvalid("Sequence number was re-used")

        tag = ciphertext[-self.algorithm.tag_bytes:]
        ciphertext = ciphertext[:-self.algorithm.tag_bytes]

        partial_iv = binascii.unhexlify("%014x"%seqno)
        iv = _xor_bytes(self.other_iv, partial_iv)

        enc_structure = ['Encrypt0', protected_serialized, self._extract_external_aad(protected_message, False, request_partiv)]
        aad = cbor.dumps(enc_structure)

        plaintext = self.algorithm.decrypt(ciphertext, tag, aad, self.other_key, iv)

        # FIXME add options from unprotected

        unprotected_message = aiocoap.message.Message(code=protected_message.code)
        unprotected_message.payload = unprotected_message.opt.decode(plaintext)

        return unprotected_message, protected[6]

    @classmethod
    def _extract_encrypted0(cls, message):
        if message.opt.object_security is None:
            raise NotAProtectedMessage("No Object-Security option present")

        serialized = message.opt.object_security or message.payload

        try:
            encrypted0 = cbor.loads(serialized)
        except ValueError:
            raise ProtectionInvalid("Error parsing the CBOR payload")

        if not isinstance(encrypted0, list) or len(encrypted0) != 3:
            raise ProtectionInvalid("CBOR payload is not structured like Encrypt0")

        try:
            protected = cbor.loads(encrypted0[0])
        except ValueError:
            raise ProtectionInvalid("Error parsing the CBOR protected data")

        return encrypted0[0], protected, encrypted0[1], encrypted0[2]

    # sequence number handling

    def new_sequence_number(self):
        retval = self.my_sequence_number
        if retval > self.algorithm.max_seqno:
            raise ValueError("Sequence number too large, context is exhausted.")
        self.my_sequence_number += 1
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

    * CID, and optionally algorithm, sender and recipient ID, and the KDF hash
      function (settings.json)
    * the master key / base key (secret.json, typically readable only for the
      user)
    * sequence numbers and replay windows (sequence.json, the only file the
      process needs write access to)

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
        def data(partname):
            return json.load(open(os.path.join(self.basedir, partname + ".json")))

        secret = data('secret')
        if 'secret_ascii' in secret:
            master_secret = secret['secret_ascii'].encode('ascii')
        else:
            master_secret = binascii.unhexlify(secret['secret_hex'])

        settings = data('settings')
        self.cid = binascii.unhexlify(settings['cid'])
        self.algorithm = algorithms[settings.get('algorithm', 'AES-CCM-64-64-128')]
        self.hashfun = hashfunctions[settings.get('kdf-hashfun', 'sha256')]

        sender_id = binascii.unhexlify(settings.get('sender-id', '00'))
        recipient_id = binascii.unhexlify(settings.get('recipient-id', '01'))
        self.my_id = {'sender': sender_id, 'recipient': recipient_id}[my_role]
        self.other_id = {'sender': recipient_id, 'recipient': sender_id}[my_role]

        self.my_key = self._kdf(master_secret, self.my_id, 'Key')
        self.my_iv = self._kdf(master_secret, self.my_id, 'IV')
        self.other_key = self._kdf(master_secret, self.other_id, 'Key')
        self.other_iv = self._kdf(master_secret, self.other_id, 'IV')

        try:
            sequence = data('sequence')
        except FileNotFoundError:
            self.my_sequence_number = 0
            self.other_replay_window = SimpleReplayWindow([])
        else:
            my_hex = binascii.hexlify(self.my_id).decode('ascii')
            other_hex = binascii.hexlify(self.other_id).decode('ascii')
            self.my_sequence_number = int(sequence['used'][my_hex])
            self.other_replay_window = SimpleReplayWindow([int(x) for x in
                sequence['seen'][other_hex]])
            if len(sequence['used']) != 1 or len(sequence['seen']) != 1:
                warnings.warn("Sequence files shared between roles are "
                        "currently not supported.")

    def _kdf(self, master_secret, role_id, out_type):
        out_bytes = {'Key': self.algorithm.key_bytes, 'IV': self.algorithm.iv_bytes}[out_type]

        info = cbor.dumps([
            self.cid,
            role_id,
            self.algorithm.value,
            out_type,
            out_bytes * 8
            ])
        # salt being null sequence is already the default of hkdf, no need to
        # be explicit again
        extracted = hkdf.hkdf_extract(None, master_secret, hash=self.hashfun)
        expanded = hkdf.hkdf_expand(extracted, info=info, hash=self.hashfun,
                length=out_bytes)
        return expanded

    # FIXME when/how will this be called?
    #
    # it might be practical to make my_sequence_number and other_replay_window
    # properties private, and provide access to them in a way that triggers
    # store or at least a delayed store.
    def _store(self):
        tmphand, tmpnam = tempfile.mkstemp(dir=self.basedir,
                prefix='.sequence-', suffix='.json', text=True)

        my_hex = binascii.hexlify(self.my_id).decode('ascii')
        other_hex = binascii.hexlify(self.other_id).decode('ascii')

        with os.fdopen(tmphand, 'w') as tmpfile:
            tmpfile.write('{\n'
                '  "used": {"%s": %d},\n'
                '  "seen": {"%s": %s}\n}'%(
                my_hex, self.my_sequence_number,
                other_hex, self.other_replay_window.seen))

        os.rename(tmpnam, os.path.join(self.basedir, 'sequence.json'))

    @classmethod
    def generate(cls, basedir):
        """Create a security context directory from default parameters and a
        random key; it is an error if that directory already exists.

        No SecurityContext object is returned immediately, as it is expected
        that the generated context can't be used immediately but first needs to
        be copied to another party and then can be opened in either the sender
        or the recipient role."""
        # *Probably*, regular random would be sufficient, because cid is not
        # critical and the master secret is fed through HMAC, but I prefer to
        # err on the side of caution here
        cid = secrets.token_bytes(nbytes=8)
        # shorter would probably be OK too (that token might be suitable to
        # even skip extraction), but for the purpose of generating conformant
        # example contexts.
        master_secret = secrets.token_bytes(nbytes=32)

        os.makedirs(basedir)
        with open(os.path.join(basedir, 'settings.json'), 'w') as settingsfile:
            settingsfile.write("{\n"
                    '  "cid": "%s",\n\n'
                    '  "sender-id": "00",\n'
                    '  "recipient-id": "01",\n'
                    '  "algorithm": "AES-CCM-64-64-128",\n'
                    '  "kdf-hashfun": "sha256"\n'
                    '}'%binascii.hexlify(cid).decode('ascii'))

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
    context to actually verify the message. Raises Not"""

    _, protected, _, _ = SecurityContext._extract_encrypted0(message)

    try:
        # FIXME raise on duplicate key
        cid = protected[4]
    except KeyError:
        raise NotAProtectedMessage("No CID present")

    return (cid, None)
