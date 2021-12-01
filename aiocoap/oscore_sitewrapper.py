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
from . import plumbingrequest
from .numbers.codes import FETCH, POST

from aiocoap.transports.oscore import OSCOREAddress

class OscoreSiteWrapper(interfaces.Resource):
    def __init__(self, inner_site, server_credentials):
        self.log = logging.getLogger('oscore-site')

        self._inner_site = inner_site
        self.server_credentials = server_credentials

    async def render(self, request):
        raise RuntimeError("OscoreSiteWrapper can only be used through the render_to_plumbingrequest interface")

    async def needs_blockwise_assembly(self, request):
        raise RuntimeError("OscoreSiteWrapper can only be used through the render_to_plumbingrequest interface")

    # FIXME: should there be a get_resources_as_linkheader that just forwards
    # all the others and indicates ;osc everywhere?

    async def render_to_plumbingrequest(self, pr):
        request = pr.request

        try:
            unprotected = oscore.verify_start(request)
        except oscore.NotAProtectedMessage:
            # ie. if no object_seccurity present
            await self._inner_site.render_to_plumbingrequest(pr)
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
        # except error.RenderableError: That happens for the Echo recovery 4.01
        #     replies, but just travels through.
        # The other errors could be ported thee but would need some better NoResponse handling.
        except oscore.ReplayError:
            if request.mtype == aiocoap.CON:
                pr.add_response(
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

        inner_pr = plumbingrequest.IterablePlumbingRequest(unprotected)
        pr_that_can_take_errors = plumbingrequest.error_to_message(inner_pr, self.log)
        # FIXME: do not create a task but run this in here (can this become a
        # feature of the aiterable PR?)
        plumbingrequest.run_driving_plumbing_request(
                pr_that_can_take_errors,
                self._inner_site.render_to_plumbingrequest(inner_pr),
                name="OSCORE response rendering for %r" % unprotected,
                )

        async for event in inner_pr:
            if event.exception is not None:
                # These are expected to be rare in handlers
                #
                # FIXME should we try to render them? (See also
                # run_driving_plumbing_request). Just raising them
                # would definitely be bad, as they might be renderable and
                # then would hit the outer message.
                self.log.warn("Turning error raised from renderer into nondescript protected error %r", event.exception)
                message = aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR)
                is_last = True
            else:
                message = event.message
                is_last = event.is_last

            protected_response, _ = sc.protect(message, seqno)
            if message.opt.observe is not None:
                # FIXME: should be done in protect
                protected_response.opt.observe = message.opt.observe
            self.log.debug("Response %r was encrypted into %r", message, protected_response)

            pr.add_response(protected_response, is_last=is_last)
            if event.is_last:
                break
        # The created task gets cancelled here because the __aiter__ result is
        # dropped and thus all interest in the inner_pr goes away
