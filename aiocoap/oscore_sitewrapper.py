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

So far, it needs to be utilized explicitly and manually at server creation. How
this will later be automated will depend on th edirection Site is going -- if
all of :meth:`aiocoap.protocol.Context.render_to_plumbing_request` can be moved
into Site wrappers, this can stay a site wrapper -- otherwise, it may need to
move in there to start render_to_plumbing_request on the unprotected requests
again. (This will also influence a future inner-blockwise implementation).
"""

# WIP: TThis is being ported out of plugtest-server, leaving out the block-wise
# and observation parts for now.

import logging

import aiocoap
from aiocoap import interfaces
from aiocoap import oscore, error

from aiocoap.transports.oscore import OSCOREAddress

class OscoreSiteWrapper(interfaces.Resource):
    def __init__(self, inner_site, server_credentials):
        self.log = logging.getLogger('oscore-site')

        self._inner_site = inner_site
        self.server_credentials = server_credentials

    async def needs_blockwise_assembly(self, request):
        if not request.opt.object_security:
            return await self._inner_site.needs_blockwise_assembly(request)

        # enable outer-blockwise
        return True

    # FIXME: should there be a get_resources_as_linkheader that just forwards
    # all the others and indicates ;osc everywhere?

    async def render(self, request):
        try:
            unprotected = oscore.verify_start(request)
        except oscore.NotAProtectedMessage:
            # ie. if no object_seccurity present
            return await self._inner_site.render(request)

        try:
            sc = self.server_credentials.find_oscore(unprotected)
        except KeyError:
            if request.mtype == aiocoap.CON:
                raise error.Unauthorized("Security context not found")
            else:
                return aiocoap.message.NoResponse

        try:
            unprotected, seqno = sc.unprotect(request)
        except error.RenderableError as e:
            # Primarily used for the Echo recovery 4.01 reply; the below could
            # be migrated there, but the behavior (at least as currently
            # encoded) is not exactly the one a no_response=26 would show, as
            # we want full responses to CONs but no responses to NONs, wheras
            # no_response=26 only flushes out an empty ACK and nothing more
            return e.to_message()
        except oscore.ReplayError:
            if request.mtype == aiocoap.CON:
                return aiocoap.Message(code=aiocoap.UNAUTHORIZED, max_age=0, payload=b"Replay detected")
            else:
                return aiocoap.message.NoResponse
        except oscore.DecodeError:
            if request.mtype == aiocoap.CON:
                raise error.BadOption("Failed to decode COSE")
            else:
                return aiocoap.message.NoResponse
        except oscore.ProtectionInvalid as e:
            if request.mtype == aiocoap.CON:
                raise error.BadRequest("Decryption failed")
            else:
                return aiocoap.message.NoResponse

        unprotected.remote = OSCOREAddress(sc, request.remote)

        self.log.debug("Request %r was unprotected into %r", request, unprotected)

        sc = sc.context_for_response()

        eventual_err = None
        try:
            response = await self._inner_site.render(unprotected)
        except error.RenderableError as err:
            try:
                response = err.to_message()
            except Exception as err:
                eventual_err = err
        except Exception as err:
            eventual_err = err
        if eventual_err is not None:
            response = aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR)
            self.log.error("An exception occurred while rendering a protected resource: %r", eventual_err, exc_info=eventual_err)

        protected_response, _ = sc.protect(response, seqno)

        self.log.debug("Response %r was encrypted into %r", response, protected_response)

        return protected_response
