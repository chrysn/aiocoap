# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from dataclasses import dataclass
from typing import Optional, List
import random

import cbor2
from cose import curves, algorithms
from cose.keys import OKPKey, CoseKey
from edhoc.roles.responder import Responder
from edhoc import messages
from edhoc.definitions import CipherSuite, CipherSuite0

from . import message, numbers, error
from .resource import Resource
from .credentials import CredentialsMap

@dataclass
class EdhocPrivateKey:
    suite: CipherSuite
    id_cred_x: dict # eg. {4: ...}
    cred_x: dict # CBOR public key, typically including "subject name": "..."
    private_key: CoseKey # more precisely an elliptic curve key matching the cipher suite

    def is_static(self):
        return self.private_key.crv == self.suite.dh_curve

@dataclass
class EdhocPublicKey:
    suite: CipherSuite
    id_cred_x: dict # eg. {4: ...}
    cred_x: dict # CBOR public key, typically including "subject name": "..."
    public_key: CoseKey # more precisely an elliptic curve key matching the cipher suite

    def is_static(self):
        return self.public_key.crv == self.suite.dh_curve

class _ResponderPool:
    def __init__(self):
        # FIXME: expire old responders
        self.responders = {}

    def get(self, key):
        return self.responders[key]

    def create_responder(self, get_peer_cred, id_cred_r, cred_r, auth_key, suites: List[CipherSuite]):
        """Pick a responder ID, build a responder given the own credentials and
        register it with the ID for as long as exchanges are expected to be
        active"""

        # FIXME: Can use full range once initial null is implemented
        # FIXME: Fall back to longer ones on demand
        good_choices = set(range(-24, 0)) | set(range(16, 24))
        # Encoded them into the bytes the API needs to later make them back to
        # integers
        good_choices = {messages.EdhocMessage.decode_bstr_id(x) for x in good_choices}
        # FIXME: Consider also which OSCORE KIDs are allocated for this in the first place
        valid_choices = good_choices ^ self.responders.keys()
        if not valid_choices:
            raise RuntimeError("All super-efficient codes used simultaneously,"
                    " please give me a break")

        c_r = random.choice(list(valid_choices))

        r = Responder(conn_idr=c_r,
                         cred_idr=id_cred_r,
                         auth_key=auth_key,
                         cred=cred_r,
                         remote_cred_cb=get_peer_cred,
                         # FIXME py-edhoc doesn't use this to the full extent yet
                         supported_ciphers=suites,
                         )

        self.responders[c_r] = r
        return r

class EdhocResource(Resource):
    def __init__(self, server_credentials: CredentialsMap):
        # This is local state that; in multi-task systems a different state set
        # may be live at the same time. Nonetheless, they come from the same
        # remote and thus hit the same server.
        #
        # (That's not to say a shared responder couldn't be switched in).
        self.responders = _ResponderPool()

        self.server_credentials = server_credentials

    async def render_post(self, request):
        # FIXME general handling of parse errors

        first = cbor2.loads(request.payload)
        # our C_R are all picked to not coincide with the possible values for
        # METHOD_CORR, and we don't do role I here yet
        # TBD: Switch over to new null start
        is_message1 = first in range(16)

        if is_message1:
            m1 = messages.MessageOne.decode(request.payload)

            if m1.corr in (0, 2):
                # FIXME precise error handling
                raise error.BadRequest("As a server, I don't see how the transport would allow me to correlate (client set corr=%d with first byte 0x%02x)" % (corr, first))
            i_am_static = m1.method in (1, 3)

            resp = self.responders.create_responder(self._get_peer_cred, *self._pick_credentials(request.opt.uri_host, i_am_static, m1.cipher_suites))

            msg_2 = resp.create_message_two(request.payload)

            return message.Message(code=numbers.Code.CHANGED, payload=msg_2)

        else:
            m3 = messages.MessageThree.decode(request.payload)

            try:
                # considering the del below ... maybe pop?
                responder = self.responders.get(m3.conn_idr)
            except KeyError:
                # FIXME precise error handling
                raise error.BadRequest("Missing message 1 context")

            # FIXME: API should be this stateful
            #assert responder.edhoc_state == EdhocState.MSG_2_SENT

            conn_idi, conn_idr, aead, hashf = responder.finalize(request.payload)
            # FIXME why do I get this back again?
            assert conn_idr == m3.conn_idr

            import logging

            logging.info('EDHOC key exchange successfully completed:')
            logging.info(f" - connection IDr: {conn_idr}")
            logging.info(f" - connection IDi: {conn_idi}")
            logging.info(f" - aead algorithm: {algorithms.CoseAlgorithm.from_id(aead)}")
            logging.info(f" - hash algorithm: {algorithms.CoseAlgorithm.from_id(hashf)}")

            logging.info(f" - OSCORE secret : {responder.exporter('OSCORE Master Secret', 16).hex()}")
            logging.info(f" - OSCORE salt   : {responder.exporter('OSCORE Master Salt', 8).hex()}")

            # FIXME are we done here? probably yes, because a second msg3
            # should err -- just we're not producing a msg4, and probably we
            # should unless there's NoResponse
            del self.responders.responders[conn_idr]

            return message.Message(code=numbers.Code.CHANGED)

    # FIXME: change from purely-static into 
    def _pick_credentials(self, uri_host: Optional[str], static: bool, suites: List[CipherSuite]):
        """Pick create_responder arguments given what is known at M1 reception.
        If credentials are found, the suites must be the one-element list of
        the requested suite (although the library probably tolerates tail
        output); if not, the first arguments will be ignored but possible
        suites can be provided for retries (although py-edhoc currently doesn't
        expose them in the error message)
        """

        potential_suites = set()

        while suites:
            # this could be done way more efficiently, but then again the list is expected to be short
            for (k, c) in self.server_credentials.items():
                if not isinstance(c, EdhocPrivateKey):
                    continue
                # currently not checking for uri_host as that can't be
                # expressed in credentials ... or can it? probably it could be,
                # it's just a FIXME
                if c.is_static() != static:
                    continue
                if c.suite not in suites:
                    potential_suites.add(c.suite)
                    continue

                # None: no need to establish the public key, it's just passed through _parse_credentials but never used
                return c.id_cred_x, (c.cred_x, None), c.private_key, [c.suite]

            suites = suites[1:]

        raise NotImplementedError("Should somehow get these potential_suites out into an error response")

    def _get_peer_cred(self, arg):
        for (k, c) in self.server_credentials.items():
            # FIXME: check suite and whether it's suitably static (hey, multiple times the compact identifiers)
            if c.id_cred_x == arg:
                return c.public_key, c.cred_x

        raise NotImplementedError("Not credentials known for peer %r and no error messages implemented", (arg, ))
