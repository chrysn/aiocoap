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

from aiocoap.resource import Resource

# OSCOREAddress is used here in a semi-placeholder capacity; it is not linked
# to a transport because the protected site is not a transport's site yet
from aiocoap.transports.oscore import OSCOREAddress

class OscoreProfileAuthzInfo(Resource):
    """An /autz-info endpoint that can perform the ACE-OSCORE profile and
    enters its context into the credentials set"""
    def __init__(self, credentials, context_getter):
        self.credentials = credentials
        # FIXME about that we have to pass a context around
        self.context_getter = context_getter
        super().__init__()

    async def render_post(self, request):
        import cbor2 as cbor
        import aiocoap
        data = cbor.loads(request.payload)
        token = data[1]
        nonce1 = data[65]

        my_as_introspection_point = 'coap://localhost/introspect'
        context = self.context_getter()
        print(f"Requesting {my_as_introspection_point} via {context}")
        introspect_request = aiocoap.Message(
                code=aiocoap.POST,
                uri=my_as_introspection_point,
                content_format=aiocoap.numbers.media_types_rev['application/ace+cbor'],
                payload=cbor.dumps({11: token}),
                )
        introspect_response = await context.request(introspect_request).response_raising
        result = cbor.loads(introspect_response.payload)
        print(result)

        audience = result[3]
        scope = result[9]
        cnf = result[8]
        assert list(cnf.keys()) == [99] # per https://github.com/ace-wg/Hackathon-108/blob/master/IANA.md
        cnf_osc = cnf[99]

        from aiocoap.util.secrets import token_bytes
        nonce2 = token_bytes(16)

        cnf_osc[6] = cnf_osc.pop(6, b"") + nonce1 + nonce2
        secctx = oscore.AceOscoreContext(cnf_osc, 'server')

        # FIXME abusing the knowledge that they're the same
        # FIXME a static name is a bad idea here
        context.client_credentials[':ace-oscore'] = secctx
        print("Set that context as the available ACE-OSCORE context")

        return aiocoap.Message(
                code=aiocoap.CHANGED,
                content_format=aiocoap.numbers.media_types_rev['application/ace+cbor'],
                payload=cbor.dumps({66: nonce2}),
                )

class OscoreSiteWrapper(interfaces.Resource):
    def __init__(self, inner_site, server_credentials):
        self.log = logging.getLogger('oscore-site')

        self._inner_site = inner_site
        self.server_credentials = server_credentials

        # FIXME about where we get that context from
        self._inner_site.add_resource(['authz-info'], OscoreProfileAuthzInfo(server_credentials, lambda: inner_site._simple_wkc.context))

    async def needs_blockwise_assembly(self, request):
        if not request.opt.object_security:
            return await self._inner_site.needs_blockwise_assembly(request)

        # enable outer-blockwise
        return True

    # FIXME: should there be a get_resources_as_linkheader that just forwards
    # all the others and indicates ;osc everywhere?

    async def render(self, request):
        try:
            recipient_id, id_context = oscore.verify_start(request)
        except oscore.NotAProtectedMessage:
            # ie. if no object_seccurity present
            return await self._inner_site.render(request)

        try:
            sc = self.server_credentials.find_oscore(recipient_id, id_context)
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

        unprotected.remote = OSCOREAddress(None, sc, request.remote)

        self.log.debug("Request %r was unprotected into %r", request, unprotected)

        try:
            response = await self._inner_site.render(unprotected)
        except error.RenderableError as err:
            response = err.to_message()
        except Exception as err:
            response = aiocoap.Message(code=aiocoap.INTERNAL_SERVER_ERROR)
            self.log.error("An exception occurred while rendering a protected resource: %r", err, exc_info=err)

        protected_response, _ = sc.protect(response, seqno)

        self.log.debug("Response %r was encrypted into %r", response, protected_response)

        return protected_response
