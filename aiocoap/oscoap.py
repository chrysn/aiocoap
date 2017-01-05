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

from aiocoap.util import secrets

import hkdf
import cbor

class Algorithm:
    pass

class AES_CCM_64_64_128(Algorithm):
    # from draft-ietf-cose-msg-24 and draft-ietf-core-object-security 3.2.1
    value = 12
    key_bytes = 32
    iv_bytes = 7 # 56 bit nonce
    tag_length = 8 # 64 bit tag

algorithms = {
        'AES-CCM-64-64-128': AES_CCM_64_64_128,
        }

hashfunctions = {
        'sha256': hashlib.sha256,
        }

class SecurityContext:
    # FIXME: protcol

    # message processing

    def _extract_enc_structure(self, message, i_am_sender):
        external_aad = [
                1, # ver
                message.code,
                self.algorithm.value,
                ]
        if message.code.is_request():
            external_aad.extend([
                message.get_request_uri(),
                # FIXME blockwise
                ])
        else:
            external_aad.extend([
                self.cid,
                self.other_id if i_am_sender else self.my_id,
                request_seq, # FIXME where will this come from?
                # FIXME blockwise
                ])

        return ['Encrypted', protected, external_aad]

    def protect(self, message):
        # any options to move out?
        inner_message = message

        # FIXME verify that cbor.dumps follows cose-msg-24 section 14
        aad = cbor.dumps(self._extract_enc_structure(message, True))
        key = self.my_key

        plaintext = inner_message.opt.encode()
        if inner_message.payload:
            plaintext += byes([0xFF])
            plaintext += inner_message.payload

        self.algorithm.encrypt(key, plaintext, aad)

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
        out_bytes = {'Key': self.algorithm.key_bytes * 8, 'IV': self.algorithm.iv_bytes}[out_type]

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
