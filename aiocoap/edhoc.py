# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Internal module containing types used inside EDHOC security contexts"""

import enum
from pathlib import Path
import random

import cbor2
import lakers

from . import oscore, credentials
from . import Message
from .numbers import POST

def load_cbor_or_edn(filename: Path):
    """Common heuristic for whether something is CBOR or EDN"""
    import cbor_diag
    import cbor2
    with filename.open('rb') as binary:
        try:
            result = cbor2.load(binary)
        except cbor2.CBORDecodeError:
            pass
        else:
            if binary.read(1) == b"":
                return result
            # else it apparently hasn't been CBOR all through...
    with filename.open() as textual:
        try:
            converted = cbor_diag.diag2cbor(textual.read())
        except ValueError:
            raise credentials.CredentialsLoadError("Data loaded from %s was recognized neither as CBOR nor CBOR Diagnostic Notation (EDN)" % filename)
        # no need to check for completeness: diag2cbor doesn't do diagnostic
        # sequences, AIU that's not even a thing
        return cbor2.loads(converted)

class CoseKeyForEdhoc:
    @classmethod
    def from_file(cls, filename: Path) -> "CoseKeyForEdhoc":
        if filename.stat().st_mode & 0o077 != 0:
            raise credentials.CredentialsLoadError("Refusing to load private key that is group or world accessible")

        loaded = load_cbor_or_edn(filename)
        if not isinstance(loaded, dict):
            raise credentials.CredentialsLoadError("Data in %s is not shaped like COSE_KEY (expected top-level dictionary)" % filename)
        if 1 not in loaded:
            raise credentials.CredentialsLoadError("Data in %s is not shaped like COSE_KEY (expected key 1 (kty) in top-level dictionary)" % filename)
        if loaded[1] != 2:
            raise credentials.CredentialsLoadError("Private key type %s is not supported (currently only 2 (EC) is supported)" % (loaded[1],))

        if loaded.get(-1) != 1:
            raise credentials.CredentialsLoadError("Private key of type EC requires key -1 (crv), currently supported values: 1 (P-256)")

        if not isinstance(loaded.get(-4), bytes) or len(loaded[-4]) != 32:
            raise credentials.CredentialsLoadError("Private key of type EC P-256 requires key -4 (d) to be a 32-byte long byte string")

        key = cls()
        key.kty = 1
        key.crv = 1
        key.d = loaded[-4]

        return key

class EdhocCredentialPair(credentials._Objectish):
    def __init__(self, suite: int, method: int, own_cred_style: str, peer_cred: dict, own_cred: dict, private_key_file: str):
        from . import edhoc

        self.suite = suite
        self.method = method
        self.own_cred = own_cred
        self.peer_cred = peer_cred

        self.own_cred_style = edhoc.OwnCredStyle(own_cred_style)

        # FIXME: We should carry around a base
        private_key_path = Path(private_key_file)
        # FIXME: We left loading the file to the user, and now we're once more
        # in a position where we guess the file type
        self.own_key = CoseKeyForEdhoc.from_file(private_key_path)

        self._established_context = None

    async def establish_context(self, wire, underlying_address, logger):
        logger.info("No OSCORE context found for EDHOC context %r, initiating one.", self)
        # FIXME: We don't support role reversal yet, but once we
        # register this context to be available for incoming
        # requests, we'll have to pick more carefully
        c_i = bytes([random.randint(0, 23)])
        initiator = lakers.EdhocInitiator()
        message_1 = initiator.prepare_message_1(c_i)

        msg1 = Message(
            code=POST,
            uri_path=['.well-known', 'edhoc'],
            payload=cbor2.dumps(True) + message_1,
        )
        msg1.remote = underlying_address
        msg2 = await wire.request(msg1).response_raising

        (c_r, id_cred_r, ead_2) = initiator.parse_message_2(msg2.payload)

        # We could look into id_cred_r, which is a CBOR encoded
        # byte string, and could start comparing ... but actually
        # EDHOC and Lakers protect us from misbinding attacks (is
        # that what they are called?), so we can just put in our
        # expected credential here
        logger.debug("EDHOC responder sent message_2 with ID_CRED_R = %r", id_cred_r)
        assert isinstance(self.own_cred, dict) and list(self.own_cred.keys()) == [14], "So far can only process CCS style own credentials a la {14: ...}, own_cred = %r" % self.own_cred
        cred_i = cbor2.dumps(self.own_cred[14])
        # FIXME more asserts or just do it right
        cred_r = cbor2.dumps(self.peer_cred[14])
        key_i = self.own_key.d
        initiator.verify_message_2(
            key_i, cred_i, cred_r,
        )  # odd that we provide that here rather than in the next function

        logger.debug("Message 2 was verified")

        return EdhocInitiatorContext(initiator, c_i, c_r, self.own_cred_style)

class EdhocInitiatorContext(
    oscore.CanProtect, oscore.CanUnprotect, oscore.SecurityContextUtils
):
    """An OSCORE context that is derived from an EDHOC exchange.

    It does not require that the EDHOC exchange has completed -- it can be set
    up by an initiator already when message 2 has been received, prepares a
    message 3 at setup time, and sends it with the first request that is sent
    through it."""
    # FIXME: Should we rather send it with *every* request that is sent before a message 4 is received implicitly?
    def __init__(self, initiator, c_ours, c_theirs, cred_i_mode):
        # Only this line is role specific
        self.message_3, _i_prk_out = initiator.prepare_message_3(cred_i_mode.as_lakers(), None)

        if initiator.selected_cipher_suite() == 2:
            self.alg_aead = oscore.algorithms["AES-CCM-16-64-128"]
            self.hashfun = oscore.hashfunctions["sha256"]
        else:
            raise RuntimeError("Unknown suite")

        # we did check for critical EADs, there was no out-of-band agreement, so 8 it is
        oscore_salt_length = 8
        # I figure that one would be ageed out-of-band as well (currently no
        # options to set/change this are known)
        self.id_context = None
        self.recipient_replay_window = oscore.ReplayWindow(32, lambda: None)

        master_secret = initiator.edhoc_exporter(0, [], self.alg_aead.key_bytes)
        master_salt = initiator.edhoc_exporter(1, [], oscore_salt_length)

        self.sender_id = c_theirs
        self.recipient_id = c_ours
        if self.sender_id == self.recipient_id:
            raise ValueError("Bad IDs: identical ones were picked")

        self.derive_keys(master_salt, master_secret)

        self.sender_sequence_number = 0
        self.recipient_replay_window.initialize_empty()

    def post_seqnoincrease(self):
        # The context is not persisted
        pass

    def protect(self, message, request_id=None, *, kid_context=True):
        outer_message, request_id = super().protect(
            message, request_id=request_id, kid_context=kid_context
        )
        if self.message_3 is not None:
            outer_message.opt.edhoc = True
            outer_message.payload = self.message_3 + outer_message.payload
            self.message_3 = None
        return outer_message, request_id

class OwnCredStyle(enum.Enum):
    """Guidance for how the own credential should be sent in an EDHOC
    exchange"""
    ByKeyId = "by-key-id"

    def as_lakers(self):
        """Convert the enum into Lakers' reepresentation of the same concept.

        The types may eventually be unified, but so far, Lakers doesn't make
        the distinctions we expect to make yet."""
        if self == self.ByKeyId:
            # FIXME: Mismatch to be fixed in lakers -- currently the only way
            # it allows sending by reference is by Key ID
            return lakers.CredentialTransfer.ByReference
        else:
            raise RuntimeError("enum variant not covered")
