# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module assists in creating OSCORE servers by proving a wrapper around a
:class:aiocoap.resource.Site. It enforces no access control, but just indicates
to the resources whether a client is authenticated by setting the request's
remote property adaequately.
"""

import logging
from typing import Optional
import uuid
import io

import cbor2
import lakers

import aiocoap
from aiocoap import interfaces
from aiocoap import oscore, error
import aiocoap.pipe
from .numbers.codes import FETCH, POST
from .numbers.optionnumbers import OptionNumber
from . import edhoc

from aiocoap.transports.oscore import OSCOREAddress


class OscoreSiteWrapper(interfaces.Resource):
    def __init__(self, inner_site, server_credentials):
        self.log = logging.getLogger("coap-server.oscore-site")

        self._inner_site = inner_site
        self.server_credentials = server_credentials

    def get_resources_as_linkheader(self):
        # Not applying any limits while WKCResource does not either
        #
        # Not adding `;osc` everywhere as that is excessive (and not telling
        # much, as one won't know *how* to get those credentials)
        return self._inner_site.get_resources_as_linkheader()

    async def render(self, request):
        raise RuntimeError(
            "OscoreSiteWrapper can only be used through the render_to_pipe interface"
        )

    async def needs_blockwise_assembly(self, request):
        raise RuntimeError(
            "OscoreSiteWrapper can only be used through the render_to_pipe interface"
        )

    async def render_to_pipe(self, pipe):
        request = pipe.request

        if request.opt.uri_path == (".well-known", "edhoc"):
            # We'll have to take that explicitly, otherwise we'd need to rely
            # on a resource to be prepared by the user in the site with a
            # cyclical reference closed after site construction
            await self._render_edhoc_to_pipe(pipe)
            return

        try:
            unprotected = oscore.verify_start(request)
        except oscore.NotAProtectedMessage:
            # ie. if no object_seccurity present
            await self._inner_site.render_to_pipe(pipe)
            return

        if request.code not in (FETCH, POST):
            raise error.MethodNotAllowed

        try:
            sc = self.server_credentials.find_oscore(unprotected)
        except KeyError:
            if request.mtype == aiocoap.CON:
                raise error.Unauthorized("Security context not found")
            else:
                return

        try:
            unprotected, seqno = sc.unprotect(request)
        except error.RenderableError as e:
            # Note that this is flying out of the unprotection (ie. the
            # security context), which is trusted to not leak unintended
            # information in unencrypted responses. (By comparison, a
            # renderable exception flying out of a user
            # render_to_pipe could only be be rendered to a
            # protected message, and we'd need to be weary of rendering errors
            # during to_message as well).
            #
            # Note that this clause is not a no-op: it protects the 4.01 Echo
            # recovery exception (which is also a ReplayError) from being
            # treated as such.
            raise e
        # The other errors could be ported thee but would need some better NoResponse handling.
        except oscore.ReplayError:
            if request.mtype == aiocoap.CON:
                pipe.add_response(
                    aiocoap.Message(
                        code=aiocoap.UNAUTHORIZED, max_age=0, payload=b"Replay detected"
                    ),
                    is_last=True,
                )
            return
        except oscore.DecodeError:
            if request.mtype == aiocoap.CON:
                raise error.BadOption("Failed to decode COSE")
            else:
                return
        except oscore.ProtectionInvalid:
            if request.mtype == aiocoap.CON:
                raise error.BadRequest("Decryption failed")
            else:
                return

        unprotected.remote = OSCOREAddress(sc, request.remote)

        self.log.debug("Request %r was unprotected into %r", request, unprotected)

        sc = sc.context_for_response()

        inner_pipe = aiocoap.pipe.IterablePipe(unprotected)
        pr_that_can_take_errors = aiocoap.pipe.error_to_message(inner_pipe, self.log)
        # FIXME: do not create a task but run this in here (can this become a
        # feature of the aiterable PR?)
        aiocoap.pipe.run_driving_pipe(
            pr_that_can_take_errors,
            self._inner_site.render_to_pipe(inner_pipe),
            name="OSCORE response rendering for %r" % unprotected,
        )

        async for event in inner_pipe:
            if event.exception is not None:
                # These are expected to be rare in handlers
                #
                # FIXME should we try to render them? (See also
                # run_driving_pipe). Just raising them
                # would definitely be bad, as they might be renderable and
                # then would hit the outer message.
                self.log.warn(
                    "Turning error raised from renderer into nondescript protected error %r",
                    event.exception,
                )
                message = aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR)
                is_last = True
            else:
                message = event.message
                is_last = event.is_last

            # FIXME: Around several places in the use of pipe (and
            # now even here), non-final events are hard-coded as observations.
            # This should shift toward the source telling, or the stream being
            # annotated as "eventually consistent resource states".
            if not is_last:
                message.opt.observe = 0

            protected_response, _ = sc.protect(message, seqno)
            if message.opt.observe is not None:
                # FIXME: should be done in protect, or by something else that
                # generally handles obs numbers better (sending the
                # oscore-reconstructed number is nice because it's consistent
                # with a proxy that doesn't want to keep a counter when it
                # knows it's OSCORE already), but starting this per obs with
                # zero (unless it was done on that token recently) would be
                # most efficient
                protected_response.opt.observe = sc.sender_sequence_number & 0xFFFFFFFF
            self.log.debug(
                "Response %r was encrypted into %r", message, protected_response
            )

            pipe.add_response(protected_response, is_last=is_last)
            if event.is_last:
                break
        # The created task gets cancelled here because the __aiter__ result is
        # dropped and thus all interest in the inner_pipe goes away

    async def _render_edhoc_to_pipe(self, pipe):
        self.log.debug("Processing request as EDHOC message 1 or 3")
        # Conveniently we don't have to care for observation, and thus can treat the rendering to a pipeline as just a rendering

        request = pipe.request

        if request.code is not POST:
            raise error.MethodNotAllowed

        if any(
            o.number.is_critical()
            for o in request.opt.option_list()
            if o.number not in (OptionNumber.URI_PATH, OptionNumber.URI_HOST)
        ):
            # FIXME: This should be done by every resource handler (see
            # https://github.com/chrysn/aiocoap/issues/268) -- this is crude
            # but better than doing nothing (and because we're rendering to a
            # pipe, chances are upcoming mitigation might not catch this)
            raise error.BadOption

        if len(request.payload) == 0:
            raise error.BadRequest

        if request.payload[0:1] == cbor2.dumps(True):
            self.log.debug("Processing request as EDHOC message 1")
            self._process_edhoc_msg12(pipe)
        else:
            self.log.debug("Processing request as EDHOC message 3")
            self._process_edhoc_msg34(pipe)

    def _process_edhoc_msg12(self, pipe):
        request = pipe.request

        origin = request.get_request_uri(local_is_server=True).removesuffix(
            "/.well-known/edhoc"
        )
        own_credential_object = self._get_edhoc_identity(origin)
        if own_credential_object is None:
            self.log.error(
                "Peer attempted EDHOC even though no EDHOC credentials are configured for %s",
                origin,
            )
            raise error.NotFound

        # FIXME lakers: Shouldn't have to commit this early, might still look at EAD1
        assert isinstance(own_credential_object.own_cred, dict) and list(
            own_credential_object.own_cred.keys()
        ) == [14], (
            "So far can only process CCS style own credentials a la {14: ...}, own_cred = %r"
            % own_credential_object.own_cred
        )
        responder = lakers.EdhocResponder(
            r=own_credential_object.own_key.d,
            cred_r=cbor2.dumps(own_credential_object.own_cred[14], canonical=True),
        )
        c_i, ead_1 = responder.process_message_1(request.payload[1:])
        if ead_1 is not None:
            self.log.error("Aborting EDHOC: EAD1 present")
            raise error.BadRequest

        used_own_identifiers = (
            self.server_credentials.find_all_used_contextless_oscore_kid()
        )
        # can't have c_r==c_i
        used_own_identifiers.add(c_i)
        # FIXME try larger ones too, but currently they wouldn't work in Lakers
        candidates = [cbor2.dumps(i) for i in range(-24, 24)]
        candidates = [c for c in candidates if c not in used_own_identifiers]
        if not candidates:
            # FIXME: LRU or timeout the contexts
            raise error.InternalServerError("Too many contexts")
        c_r = candidates[0]
        message_2 = responder.prepare_message_2(
            own_credential_object.own_cred_style.as_lakers(), c_r, None
        )

        credentials_entry = edhoc.EdhocResponderContext(
            responder,
            c_i,
            c_r,
            self.server_credentials,
            self.log,
        )
        # FIXME we shouldn't need arbitrary keys
        self.server_credentials[":" + uuid.uuid4().hex] = credentials_entry

        pipe.add_response(
            aiocoap.Message(code=aiocoap.CHANGED, payload=message_2), is_last=True
        )

    def _process_edhoc_msg34(self, pipe):
        request = pipe.request

        payload = io.BytesIO(request.payload)
        try:
            c_r = cbor2.load(payload)
        except cbor2.CBORDecodeError:
            self.log.error("Message 3 received without valid CBOR start")
            raise error.BadRequest
        message_3 = payload.read()

        if isinstance(c_r, int) and not isinstance(c_r, bool) and -24 <= c_r < 23:
            c_r = cbor2.dumps(c_r)
        if not isinstance(c_r, bytes):
            self.log.error(f"Message 3 received with invalid C_R {c_r:r}")
            raise error.BadRequest

        # Our lookup is modelled expecting OSCORE header objects, so we rebuild one
        unprotected = {oscore.COSE_KID: c_r}

        try:
            sc = self.server_credentials.find_oscore(unprotected)
        except KeyError:
            self.log.error(
                f"No OSCORE context found with recipient_id / c_r matching {c_r!r}"
            )
            raise error.BadRequest

        if not isinstance(sc, edhoc.EdhocResponderContext):
            raise error.BadRequest

        message_4 = sc._offer_message_3(message_3)

        pipe.add_response(
            aiocoap.Message(code=aiocoap.CHANGED, payload=message_4), is_last=True
        )

    def _get_edhoc_identity(self, origin: str) -> Optional[edhoc.EdhocCredentials]:
        """With lakers-python 0.3.1, we can effectively only have one identity
        per host; expect this to change once we gain access to EAD1 (plus more
        when there are more methods or cipher suites)
        """

        # That this works is a flaw of the credentials format by itself
        candidate = self.server_credentials.get(origin + "/*")
        if not isinstance(candidate, edhoc.EdhocCredentials):
            # FIXME not really a pair needed is it?
            return None
        return candidate
