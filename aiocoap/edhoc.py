# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Internal module containing types used inside EDHOC security contexts"""

import abc
import enum
import io
from pathlib import Path
import random
from typing import Optional, Dict, Literal
import os

import cbor2
import lakers

from . import oscore, credentials, error
from . import Message
from .numbers import POST


def load_cbor_or_edn(filename: Path):
    """Common heuristic for whether something is CBOR or EDN"""
    import cbor_diag
    import cbor2

    with filename.open("rb") as binary:
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
            raise credentials.CredentialsLoadError(
                "Data loaded from %s was recognized neither as CBOR nor CBOR Diagnostic Notation (EDN)"
                % filename
            )
        # no need to check for completeness: diag2cbor doesn't do diagnostic
        # sequences, AIU that's not even a thing
        return cbor2.loads(converted)


class CoseKeyForEdhoc:
    kty: int
    crv: int
    d: bytes

    @classmethod
    def from_file(cls, filename: Path) -> "CoseKeyForEdhoc":
        """Load a key from a file (in CBOR or EDN), asserting that the file is not group/world readable"""
        if filename.stat().st_mode & 0o077 != 0:
            raise credentials.CredentialsLoadError(
                "Refusing to load private key that is group or world accessible"
            )

        loaded = load_cbor_or_edn(filename)
        return cls.from_map(loaded)

    @classmethod
    def from_map(cls, key: dict) -> "CoseKeyForEdhoc":
        if not isinstance(key, dict):
            raise credentials.CredentialsLoadError(
                "Data is not shaped like COSE_KEY (expected top-level dictionary)"
            )
        if 1 not in key:
            raise credentials.CredentialsLoadError(
                "Data is not shaped like COSE_KEY (expected key 1 (kty) in top-level dictionary)"
            )
        if key[1] != 2:
            raise credentials.CredentialsLoadError(
                "Private key type %s is not supported (currently only 2 (EC) is supported)"
                % (key[1],)
            )

        if key.get(-1) != 1:
            raise credentials.CredentialsLoadError(
                "Private key of type EC requires key -1 (crv), currently supported values: 1 (P-256)"
            )

        if not isinstance(key.get(-4), bytes) or len(key[-4]) != 32:
            raise credentials.CredentialsLoadError(
                "Private key of type EC P-256 requires key -4 (d) to be a 32-byte long byte string"
            )

        if any(k not in (1, -1, -4) for k in key):
            raise credentials.CredentialsLoadError(
                "Extraneous data in key, consider allow-listing the item if acceptable"
            )

        s = cls()
        s.kty = 2  # EC
        s.crv = 1  # P-256
        s.d = key[-4]

        return s

    def secret_to_map(self) -> dict:
        # kty: EC, crv: P-256, d: ...
        return {1: self.kty, -1: self.crv, -4: self.d}

    # Should we deprecate filename, add a generate_in_file method? (It's there
    # because generate originally depended on a file system)
    @classmethod
    def generate(cls, filename: Optional[Path] = None) -> "CoseKeyForEdhoc":
        """Generate a key inside a file

        This returns the generated private key.
        """

        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(curve=ec.SECP256R1())

        s = cls()
        s.kty = 2  # EC
        s.crv = 1  # P-256
        s.d = key.private_numbers().private_value.to_bytes(32, "big")

        if filename is not None:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            descriptor = os.open(filename, flags, mode=0o600)
            try:
                with open(descriptor, "wb") as keyfile:
                    cbor2.dump(s.secret_to_map(), keyfile)
            except Exception:
                filename.unlink()
                raise

        return s

    def as_ccs(
        self, kid: Optional[bytes], subject: Optional[str]
    ) -> Dict[Literal[14], dict]:
        """Given a key, generate a corresponding KCCS"""

        from cryptography.hazmat.primitives.asymmetric import ec

        private = ec.derive_private_key(int.from_bytes(self.d, "big"), ec.SECP256R1())
        public = private.public_key()

        x = public.public_numbers().x.to_bytes(32, "big")
        y = public.public_numbers().y.to_bytes(32, "big")
        # kty: EC2, crv: P-256, x, y
        cosekey = {1: 2, -1: 1, -2: x, -3: y}
        if kid is not None:
            cosekey[2] = kid
        # cnf: COSE_Key
        credential_kccs: dict = {8: {1: cosekey}}
        if subject is not None:
            credential_kccs[2] = subject

        # kccs: cnf
        return {14: credential_kccs}


class EdhocCredentials(credentials._Objectish):
    own_key: Optional[CoseKeyForEdhoc]
    suite: int
    method: int
    own_cred: Optional[dict]
    peer_cred: Optional[dict]

    def __init__(
        self,
        suite: int,
        method: int,
        own_cred_style: Optional[str] = None,
        peer_cred: Optional[dict] = None,
        own_cred: Optional[dict] = None,
        private_key_file: Optional[str] = None,
        private_key: Optional[dict] = None,
    ):
        from . import edhoc

        self.suite = suite
        self.method = method
        self.own_cred = own_cred
        self.peer_cred = peer_cred

        if private_key_file is not None and private_key is not None:
            raise credentials.CredentialsLoadError(
                "private_key is mutually exclusive with private_key_file"
            )
        if private_key_file is not None:
            # FIXME: We should carry around a base
            private_key_path = Path(private_key_file)
            # FIXME: We left loading the file to the user, and now we're once more
            # in a position where we guess the file type
            self.own_key = CoseKeyForEdhoc.from_file(private_key_path)
        elif private_key is not None:
            self.own_key = CoseKeyForEdhoc.from_map(private_key)
        else:
            self.own_key = None

        if (own_cred is None) != (own_cred_style is None) or (own_cred is None) != (
            self.own_key is None
        ):
            raise credentials.CredentialsLoadError(
                "If own credentials are given, all of own_cred, own_cred_style and private_key(_path) need to be given"
            )

        if own_cred_style is None:
            self.own_cred_style = None
        else:
            self.own_cred_style = edhoc.OwnCredStyle(own_cred_style)

        # FIXME: This is only used on the client side, and expects that all parts (own and peer) are present
        self._established_context = None

    def find_edhoc_by_id_cred_peer(self, id_cred_peer):
        if self.peer_cred is None:
            return None
        if 14 not in self.peer_cred:
            # Only recognizing CCS so far
            return None

        if id_cred_peer == cbor2.dumps(self.peer_cred[14], canonical=True):
            # credential by value
            return cbor2.dumps(self.peer_cred[14], canonical=True)

        # cnf / COS_Key / kid, should be present in all CCS
        kid = self.peer_cred[14][8][1].get(2)
        if kid is not None and id_cred_peer == kid:
            # credential by kid
            return cbor2.dumps(self.peer_cred[14], canonical=True)

    def peer_cred_is_unauthenticated(self):
        # FIXME: This is rather weird internal API, and rather weird
        # format-wise -- but it will suffice until credentials are rewritten.
        return self.peer_cred is not None and self.peer_cred == {
            "unauthenticated": True
        }

    async def establish_context(
        self,
        wire,
        underlying_address,
        underlying_proxy_scheme,
        underlying_uri_host,
        logger,
    ):
        logger.info(
            "No OSCORE context found for EDHOC context %r, initiating one.", self
        )
        # FIXME: We don't support role reversal yet, but once we
        # register this context to be available for incoming
        # requests, we'll have to pick more carefully
        c_i = bytes([random.randint(0, 23)])
        initiator = lakers.EdhocInitiator()
        message_1 = initiator.prepare_message_1(c_i)

        msg1 = Message(
            code=POST,
            proxy_scheme=underlying_proxy_scheme,
            uri_host=underlying_uri_host,
            uri_path=[".well-known", "edhoc"],
            payload=cbor2.dumps(True) + message_1,
        )
        msg1.remote = underlying_address
        msg2 = await wire.request(msg1).response_raising

        (c_r, id_cred_r, ead_2) = initiator.parse_message_2(msg2.payload)

        assert isinstance(self.own_cred, dict) and list(self.own_cred.keys()) == [14], (
            "So far can only process CCS style own credentials a la {14: ...}, own_cred = %r"
            % self.own_cred
        )
        cred_i = cbor2.dumps(self.own_cred[14], canonical=True)
        key_i = self.own_key.d

        logger.debug("EDHOC responder sent message_2 with ID_CRED_R = %r", id_cred_r)
        if self.peer_cred == {"unauthenticated": True}:
            # Not doing further checks (eg. for trailing bytes) or re-raising: This
            # was already checked by lakers
            parsed = cbor2.loads(id_cred_r)

            if not isinstance(parsed, dict):
                raise credentials.CredentialsMissingError(
                    "Peer presented credential-by-reference when no credential was pre-agreed"
                )

            cred_r = id_cred_r
        else:
            # We could look into id_cred_r, which is a CBOR encoded
            # byte string, and could start comparing ... but actually
            # EDHOC and Lakers protect us from misbinding attacks (is
            # that what they are called?), so we can just put in our
            # expected credential here
            #
            # FIXME: But looking into it might give us a better error than just
            # "Mac2 verification failed"

            # FIXME add assert on the structure or start doing the
            # generalization that'll fail at startup
            cred_r = cbor2.dumps(self.peer_cred[14], canonical=True)

        initiator.verify_message_2(
            key_i,
            cred_i,
            cred_r,
        )  # odd that we provide that here rather than in the next function

        logger.debug("Message 2 was verified")

        return EdhocInitiatorContext(initiator, c_i, c_r, self.own_cred_style, logger)


class _EdhocContextBase(
    oscore.CanProtect, oscore.CanUnprotect, oscore.SecurityContextUtils
):
    def __init__(self, logger):
        self.log = logger

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
        if (
            isinstance(edhoc_context, lakers.EdhocResponder)
            or edhoc_context.selected_cipher_suite() == 2
        ):
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

        self.log.debug("EDHOC context %r ready for OSCORE operation", self)

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
    def __init__(self, initiator, c_ours, c_theirs, cred_i_mode, logger):
        super().__init__(logger)

        # Only this line is role specific
        self._message_3, _i_prk_out = initiator.prepare_message_3(
            cred_i_mode.as_lakers(), None
        )

        self._make_ready(initiator, c_ours, c_theirs)

    def message_3_to_include(self) -> Optional[bytes]:
        if self._message_3 is not None:
            result = self._message_3
            self._message_3 = None
            return result
        return None


class EdhocResponderContext(_EdhocContextBase):
    def __init__(self, responder, c_i, c_r, server_credentials, logger):
        super().__init__(logger)

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
            raise RuntimeError(
                "EDHOC has not completed yet, waiting for message 3, can not protect own messages yet"
            )
        return super().protect(*args, **kwargs)

    def unprotect(self, protected_message, request_id=None):
        if self._incomplete:
            if not protected_message.opt.edhoc:
                self.log.error(
                    "OSCORE failed: No EDHOC message 3 received and none present"
                )
                raise error.BadRequest("EDHOC incomplete")

            payload_stream = io.BytesIO(protected_message.payload)
            # discarding result -- just need to have a point to split
            _ = cbor2.load(payload_stream)
            m3len = payload_stream.tell()
            message_3 = protected_message.payload[:m3len]

            id_cred_i, ead_3 = self._responder.parse_message_3(message_3)
            if ead_3 is not None:
                self.log.error("Aborting EDHOC: EAD3 present")
                raise error.BadRequest

            try:
                (cred_i, claims) = self._server_credentials.find_edhoc_by_id_cred_peer(
                    id_cred_i
                )
            except KeyError:
                self.log.error(
                    "Aborting EDHOC: No credentials found for client with id_cred_i=h'%s'",
                    id_cred_i.hex(),
                )
                raise error.BadRequest

            self.authenticated_claims.extend(claims)

            self._responder.verify_message_3(cred_i)

            self._make_ready(self._responder, self.recipient_id, self.sender_id)
            self._incomplete = False

            protected_message = protected_message.copy(
                edhoc=False, payload=protected_message.payload[m3len:]
            )

        return super().unprotect(protected_message, request_id)


class OwnCredStyle(enum.Enum):
    """Guidance for how the own credential should be sent in an EDHOC
    exchange"""

    ByKeyId = "by-key-id"
    ByValue = "by-value"

    def as_lakers(self):
        """Convert the enum into Lakers' reepresentation of the same concept.

        The types may eventually be unified, but so far, Lakers doesn't make
        the distinctions we expect to make yet."""
        if self == self.ByKeyId:
            # FIXME: Mismatch to be fixed in lakers -- currently the only way
            # it allows sending by reference is by Key ID
            return lakers.CredentialTransfer.ByReference
        if self == self.ByValue:
            return lakers.CredentialTransfer.ByValue
        else:
            raise RuntimeError("enum variant not covered")
