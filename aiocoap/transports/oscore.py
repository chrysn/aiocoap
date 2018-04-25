# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

# WORK IN PROGRESS: TransportEndpoint has been renamed to MessageInterface
# here, but actually we'll be providing a RequestInterface -- that's one of the
# reasons why RequestInterface, TokenInterface and MessageInterface were split
# in the first place.

"""This module implements a RequestProvider for OSCORE. As such, it takes
routing ownership of requests that it has a security context available for, and
sends off the protected messages via another transport.

This transport is a bit different from the others because it doesn't have its
dedicated URI scheme, but purely relies on preconfigured contexts.

So far, this transport only deals with outgoing requests, and does not help in
building an OSCORE server. (Some code that could be used here in future resides
in `contrib/oscore-plugtest/plugtest-server` as the `ProtectedSite` class.
"""

import asyncio
from collections import namedtuple

from .. import interfaces, message, credentials, oscore

class OSCOREAddress(
        namedtuple("_OSCOREAddress", ["transport", "security_context", "underlying_address"]),
        interfaces.EndpointAddress
        ):
    """Remote address type for :cls:`TransportOSCORE`."""

    def __repr__(self):
        return "<%s in context %r to %r>"%(type(self).__name__, self.security_context, self.underlying_address)

    @property
    def hostinfo(self):
        if self.underlying_address is None:
            raise ValueError("No underlying address populated that could be used to derive a hostinfo")
        return self.underlying_address.hostinfo

    is_multicast = False

    maximum_payload_size = 1024
    maximum_block_size_exp = 6

class TransportOSCORE(interfaces.RequestProvider):
    def __init__(self, context, forward_context):
        self._context = context
        self._wire = forward_context

        if self._context.loop is not self._wire.loop:
            # TransportOSCORE is not designed to bridge loops -- would probably
            # be possible, but incur confusion that is most likely well avoidable
            raise ValueError("Wire and context need to share an asyncio loop")

        self.loop = self._context.loop
        self.log = self._context.log

    #
    # implement RequestInterface
    #

    async def fill_or_recognize_remote(self, message):
        if isinstance(message, OSCOREAddress) and message.transport is self:
            return True
        if message.opt.object_security is not None:
            # double oscore is not specified; using this fact to make `._wire
            # is ._context` an option
            return False

        try:
            secctx = self._context.client_credentials.credentials_from_request(message)
        except credentials.CredentialsMissingError:
            return False

        # FIXME: it'd be better to have a "get me credentials *of this type* if they exist"
        if isinstance(secctx, oscore.SecurityContext):
            message.remote = OSCOREAddress(self, secctx, None)
            return True
        else:
            return False

    def request(self, request):
        msg = request.request

        secctx = msg.remote.security_context

        protected, original_request_seqno = secctx.protect(msg)
        # FIXME where should this be called from?
        secctx._store()

        wire_request = self._wire.request(protected)

        self.loop.create_task(self._request(request, wire_request, secctx, original_request_seqno))

    async def _request(self, request, wire_request, secctx, original_request_seqno):

        # tempting as it would be, we can't access the request as a
        # PlumbingRequest here, because it is a BlockwiseRequest to handle
        # outer blockwise.
        # (Might be a good idea to model those after PlumbingRequest too,
        # though).

        def _check(more, unprotected_response):
            if more and not unprotected_response.code.is_successful():
                self.log.warning("OSCORE protected message contained observe, but unprotected code is unsuccessful. Ignoring the observation.")
                return False
            return more

        try:
            protected_response = await wire_request.response
            unprotected_response, _ = secctx.unprotect(protected_response, original_request_seqno)
            secctx._store()

            unprotected_response.remote = OSCOREAddress(self, secctx, protected_response.remote)
            # FIXME: if i could tap into the underlying PlumbingRequest, that'd
            # be a lot easier -- and also get rid of the awkward _check
            # code moved into its own function just to avoid duplication.
            more = protected_response.opt.observe is not None
            more = _check(more, unprotected_response)
            request.add_response(unprotected_response, is_last=not more)

            if not more:
                return

            async for protected_response in wire_request.observation:
                unprotected_response, _ = secctx.unprotect(protected_response, original_request_seqno)
                secctx._store()

                more = protected_response.opt.observe is not None
                more = _check(more, unprotected_response)

                unprotected_response.remote = OSCOREAddress(self, secctx, protected_response.remote)
                # FIXME: discover is_last from the underlying response
                request.add_response(unprotected_response, is_last=not more)

                if not more:
                    return
            request.add_exception(NotImplementedError("End of observation"
                " should have been indicated in is_last, see above lines"))
        except Exception as e:
            request.add_exception(e)
        finally:
            # FIXME: no way yet to cancel observations exists yet, let alone
            # one that can be used in a finally clause (ie. won't raise
            # something else if the observation terminated server-side)
            pass
            #if wire_request.observation is not None:
            #    wire_request.observation.cancel()

    async def shutdown(self):
        # Nothing to do here yet; the individual requests will be shut down by
        # their underlying transports
        pass
