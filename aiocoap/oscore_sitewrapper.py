# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module assists in creating OSCORE servers by proving a wrapper around a
:class:aiocoap.resource.Site. It enforces no access control, but just indicates
to the resources whether a client is authenticated by setting the request's
remote property adaequately.
"""

import logging

import aiocoap
from aiocoap import interfaces
from aiocoap import oscore, error
import aiocoap.pipe
from .numbers.codes import FETCH, POST

from aiocoap.transports.oscore import OSCOREAddress

class OscoreSiteWrapper(interfaces.Resource):
    def __init__(self, inner_site, server_credentials):
        self.log = logging.getLogger('oscore-site')

        self._inner_site = inner_site
        self.server_credentials = server_credentials

    async def render(self, request):
        raise RuntimeError("OscoreSiteWrapper can only be used through the render_to_pipe interface")

    async def needs_blockwise_assembly(self, request):
        raise RuntimeError("OscoreSiteWrapper can only be used through the render_to_pipe interface")

    # FIXME: should there be a get_resources_as_linkheader that just forwards
    # all the others and indicates ;osc everywhere?

    async def render_to_pipe(self, pipe):
        request = pipe.request

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
                        aiocoap.Message(code=aiocoap.UNAUTHORIZED, max_age=0, payload=b"Replay detected"),
                        is_last=True)
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
                self.log.warn("Turning error raised from renderer into nondescript protected error %r", event.exception)
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
                protected_response.opt.observe = sc.sender_sequence_number & 0xffffffff
            self.log.debug("Response %r was encrypted into %r", message, protected_response)

            pipe.add_response(protected_response, is_last=is_last)
            if event.is_last:
                break
        # The created task gets cancelled here because the __aiter__ result is
        # dropped and thus all interest in the inner_pipe goes away
