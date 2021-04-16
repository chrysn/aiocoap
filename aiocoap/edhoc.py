# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from typing import Optional, List
import random

import cbor2
from cose import OKP, CoseEllipticCurves, CoseAlgorithms, CoseHeaderKeys, KeyOps
from edhoc.roles.responder import Responder
from edhoc import messages

from . import message, numbers, error
from .resource import Resource

class _ResponderPool:
    def __init__(self):
        # FIXME: expire old responders
        self.responders = {}

    def get(self, key):
        return self.responders[key]

    def create_responder(self, get_peer_cred, id_cred_r, cred_r, auth_key, suites: List[int]):
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
                         peer_cred=get_peer_cred,
                         # FIXME py-edhoc doesn't use this to the full extent yet
                         supported_ciphers=suites,
                         )

        self.responders[c_r] = r
        return r

class EdhocResource(Resource):
    def __init__(self):
        # This is local state that; in multi-task systems a different state set
        # may be live at the same time. Nonetheless, they come from the same
        # remote and thus hit the same server.
        #
        # (That's not to say a shared responder couldn't be switched in).
        self.responders = _ResponderPool()

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
            logging.info(f" - aead algorithm: {CoseAlgorithms(aead)}")
            logging.info(f" - hash algorithm: {CoseAlgorithms(hashf)}")

            logging.info(f" - OSCORE secret : {responder.exporter('OSCORE Master Secret', 16).hex()}")
            logging.info(f" - OSCORE salt   : {responder.exporter('OSCORE Master Salt', 8).hex()}")

            # FIXME are we done here? probably yes, because a second msg3
            # should err -- just we're not producing a msg4, and probably we
            # should unless there's NoResponse
            del self.responders.responders[conn_idr]

            return message.Message(code=numbers.Code.CHANGED)

    # FIXME: change from purely-static into 
    def _pick_credentials(self, uri_host: Optional[str], static: bool, suites: List[int]):
        """Pick create_responder arguments given what is known at M1 reception.
        If credentials are found, the suites must be the one-element list of
        the requested suite (although the library probably tolerates tail
        output); if not, the first arguments will be ignored but possible
        suites can be provided for retries (although py-edhoc currently doesn't
        expose them in the error message)
        """
        if not static:
            # private signature key
            private_key = OKP(
                crv=CoseEllipticCurves.ED25519,
                alg=CoseAlgorithms.EDDSA,
                d=bytes.fromhex("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94"))

            # for this the client has a signature key stored (even though it doesn't verify)
            cert = b"we don't *really* use this"
            cred_id = {int(CoseHeaderKeys.X5_T): [int(CoseAlgorithms.SHA_256_64), bytes.fromhex('6844078A53F312F5')]}

            return cred_id, cert, private_key, [0]
        else:
            # for this the client has an RPK stored
            cred_id = {4: b'serverRPK'}
            # from running once with OKP.generate_key(algorithm=CoseAlgorithms.EDDSA,
            # key_ops=KeyOps.DERIVE_KEY)
            private_key = b'p\x05\x90#\xe2:\xdd\x08\xd68\x8d\xcb\x16\xd5\r\x83\xe8\xaa\x18O<\x92@\t\xc7+\xab\xb2\x89\xb60e'
            # to be shared with client
            public_key = b'J&\xddi\xe9\x93\xbe\xc5\x9a\xb7\xbfG)\t\x1f\x1e%\x16\xb9\xac\xed\xfe\x9d\xccX\x8c\xa1\xaf\x82PlT'
            cose_private_key = OKP(
                crv=CoseEllipticCurves.X25519,
                alg=CoseAlgorithms.EDDSA,
                d=private_key,
                x=public_key,
                )

            # works also without the dumps but then the _local_authkey is not parsed, which doesn't hurt anything but is just odd
            public_key = cbor2.dumps({1: 1, -1: 4, -2: public_key, "subject name": ""})
            return cred_id, public_key, cose_private_key, [0]

#         # direct override for marco to get the test vector keys in
# 
#         cred_id = {4: b'\x07'}
#         # from running once with OKP.generate_key(algorithm=CoseAlgorithms.EDDSA,
#         # key_ops=KeyOps.DERIVE_KEY)
#         private_key = bytes.fromhex('bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0')
#         # to be shared with client
#         public_key = bytes.fromhex("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32")
#         cose_private_key = OKP(
#             crv=CoseEllipticCurves.X25519,
#             alg=CoseAlgorithms.EDDSA,
#             d=private_key,
#             x=public_key,
#             )
#         return cred_id, {1: 1, -1: 4, -2: public_key, "subject name": ""}, cose_private_key, [0]

    def _get_peer_cred(self, arg):
        if arg == b"clientRPK":
#             return {1: 1, -1: 4, -2: b'\x8dP\x88\xba\x0fL\xc6\xd6\npVP\xfb\xd3)x\xdc\xc0<\xd1\xe4~\x96\n\xb0\x90\x8f\xa1\xb8;6\x0e', "subject name": ""}
#             return OKP(
#                     crv=CoseEllipticCurves.X25519,
#                     alg=CoseAlgorithms.EDDSA,
#                     # copied from own_key_for_static of client
#                     x=b'\x8dP\x88\xba\x0fL\xc6\xd6\npVP\xfb\xd3)x\xdc\xc0<\xd1\xe4~\x96\n\xb0\x90\x8f\xa1\xb8;6\x0e',
#                     )
            return cbor2.dumps({1: 1, -1: 4, -2: b'\x8dP\x88\xba\x0fL\xc6\xd6\npVP\xfb\xd3)x\xdc\xc0<\xd1\xe4~\x96\n\xb0\x90\x8f\xa1\xb8;6\x0e', "subject name": ""})

        if arg == 12:
            return cbor2.dumps({1: 1, -1: 4, -2: bytes.fromhex('2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71'), "subject name": ""})

        if arg == {34: [-15, b'p]XE\xf3o\xc6\xa6']}:
            # The "never used anyway" still has to match what the client sends, or signature_(or_mac)_3 will fail verification
            return (cbor2.dumps("never used anyway"),
                    # copied from client
                    OKP(
                        alg=CoseAlgorithms.EDDSA,
                        crv=CoseEllipticCurves.ED25519,
                        x=bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
                    ))

        raise RuntimeError("Oi, can't find %r", (arg, ))
