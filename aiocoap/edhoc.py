# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Internal module containing types used inside EDHOC security contexts"""

import abc
import enum
import io
from pathlib import Path
import random
from typing import Optional

import cbor2
import lakers

from . import oscore, credentials, error
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
    kty: int
    crv: int
    d: bytes

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

    def find_edhoc_by_id_cred_peer(self, id_cred_peer):
        if 14 not in self.peer_cred:
            # Only recognizing CCS so far
            return None

        if id_cred_peer == self.peer_cred[14]:
            # credential by value
            return cbor2.dumps(self.peer_cred[14])

        # cnf / COS_Key / kid, should be present in all CCS
        kid = self.peer_cred[14][8][1].get(2)
        if kid is not None and id_cred_peer == kid:
            # credential by kid
            return cbor2.dumps(self.peer_cred[14])

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

class _EdhocContextBase(
    oscore.CanProtect, oscore.CanUnprotect, oscore.SecurityContextUtils
):
    def post_seqnoincrease(self):
        # The context is not persisted
        pass

    def protect(self, message, request_id=None, *, kid_context=True):
        outer_message, request_id = super().protect(
            message, request_id=request_id, kid_context=kid_context
        )
        message_3 = self.message_3_to_include()
        if message_3 is not None:
            outer_message.opt.edhoc = True
            outer_message.payload = message_3 + outer_message.payload
        return outer_message, request_id

    def _make_ready(self, edhoc_context, c_ours, c_theirs):
        # FIXME: both should offer this
        if isinstance(edhoc_context, lakers.EdhocResponder) or edhoc_context.selected_cipher_suite() == 2:
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

        master_secret = edhoc_context.edhoc_exporter(0, [], self.alg_aead.key_bytes)
        master_salt = edhoc_context.edhoc_exporter(1, [], oscore_salt_length)

        self.sender_id = c_theirs
        self.recipient_id = c_ours
        if self.sender_id == self.recipient_id:
            raise ValueError("Bad IDs: identical ones were picked")

        self.derive_keys(master_salt, master_secret)

        self.sender_sequence_number = 0
        self.recipient_replay_window.initialize_empty()

    @abc.abstractmethod
    def message_3_to_include(self) -> Optional[bytes]:
        """An encoded message_3 to include in outgoing messages

        This may modify self to only return something once."""

class EdhocInitiatorContext(_EdhocContextBase):
    """An OSCORE context that is derived from an EDHOC exchange.

    It does not require that the EDHOC exchange has completed -- it can be set
    up by an initiator already when message 2 has been received, prepares a
    message 3 at setup time, and sends it with the first request that is sent
    through it."""
    # FIXME: Should we rather send it with *every* request that is sent before a message 4 is received implicitly?
    def __init__(self, initiator, c_ours, c_theirs, cred_i_mode):
        # Only this line is role specific
        self._message_3, _i_prk_out = initiator.prepare_message_3(cred_i_mode.as_lakers(), None)

        self._make_ready(initiator, c_ours, c_theirs)

    def message_3_to_include(self) -> Optional[bytes]:
        if self._message_3 is not None:
            result = self._message_3
            self._message_3 = None
            return result
        return None

class EdhocResponderContext(_EdhocContextBase):
    def __init__(self, responder, c_i, c_r, server_credentials):
        # storing them where they will later be overwritten with themselves
        self.recipient_id = c_r
        self.sender_id = c_i

        self._responder = responder
        # Through these we'll look up id_cred_i
        self._server_credentials = server_credentials

        self.authenticated_claims = []

        # Not sure why mypy even tolerates this -- we're clearly not ready for
        # a general protect/unprotect, and things only work because all
        # relevant functions get their checks introduced
        self._incomplete = True

    def message_3_to_include(self) -> Optional[bytes]:
        # as a responder we never send one
        return None

    def get_oscore_context_for(self, unprotected):
        if oscore.COSE_KID_CONTEXT in unprotected:
            return None
        if unprotected.get(oscore.COSE_KID) == self.recipient_id:
            return self

    def find_all_used_contextless_oscore_kid(self) -> set[bytes]:
        return set((self.recipient_id,))

    def protect(self, *args, **kwargs):
        if self._incomplete:
            raise RuntimeError("EDHOC has not completed yet, waiting for message 3, can not protect own messages yet")
        return super().protect(*args, **kwargs)

    def unprotect(self, protected_message, request_id=None):
        if self._incomplete:
            if not protected_message.opt.edhoc:
                raise error.BadRequest("EDHOC incomplete")

            payload_stream = io.BytesIO(protected_message.payload)
            # discarding result -- just need to have a point to split
            _ = cbor2.load(payload_stream)
            m3len = payload_stream.tell()
            message_3 = protected_message.payload[:m3len]

            id_cred_i, ead_3 = self._responder.parse_message_3(message_3)
            if ead_3 is not None:
                raise error.BadRequest

            try:
                (cred_i, claims) = self._server_credentials.find_edhoc_by_id_cred_peer(id_cred_i)
            except KeyError:
                raise error.BadRequest

            self.authenticated_claims.extend(claims)

            self._responder.verify_message_3(cred_i)

            self._make_ready(self._responder, self.recipient_id, self.sender_id)
            self._incomplete = False

            protected_message = protected_message.copy(edhoc=False, payload=protected_message.payload[m3len:])

        return super().unprotect(protected_message, request_id)



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
