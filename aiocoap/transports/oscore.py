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

In outgoing request, this transport automatically handles Echo options that
appear to come from RFC8613 Appendix B.1.2 style servers. They indicate that
the server could not process the request initially, but could do so if the
client retransmits it with an appropriate Echo value.

Unlike other transports that could (at least in theory) be present multiple
times in :attr:`aiocoap.protocol.Context.request_interfaces` (eg. because there
are several bound sockets), this is only useful once in there, as it has no own
state, picks the OSCORE security context from the CoAP
:attr:`aiocoap.protocol.Context.client_credentials` when populating the remote
field, and handles any populated request based ono its remote.security_context
property alone.
"""

from collections import namedtuple
from functools import wraps

from .. import interfaces, credentials, oscore
from ..numbers import UNAUTHORIZED

class OSCOREAddress(
        namedtuple("_OSCOREAddress", ["security_context", "underlying_address"]),
        interfaces.EndpointAddress
        ):
    """Remote address type for :cls:`TransportOSCORE`."""

    def __repr__(self):
        return "<%s in context %r to %r>"%(type(self).__name__, self.security_context, self.underlying_address)

    def _requires_ua(f):
        @wraps(f)
        def wrapper(self):
            if self.underlying_address is None:
                raise ValueError("No underlying address populated that could be used to derive a hostinfo")
            return f(self)
        return wrapper

    @property
    @_requires_ua
    def hostinfo(self):
        return self.underlying_address.hostinfo

    @property
    @_requires_ua
    def hostinfo_local(self):
        return self.underlying_address.hostinfo_local

    @property
    @_requires_ua
    def uri_base(self):
        return self.underlying_address.uri_base

    @property
    @_requires_ua
    def uri_base_local(self):
        return self.underlying_address.uri_base_local

    @property
    @_requires_ua
    def scheme(self):
        return self.underlying_address.scheme

    @property
    def authenticated_claims(self):
        return self.security_context.authenticated_claims

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

        # Keep current requests. This is not needed for shutdown purposes (see
        # .shutdown), but because Python 3.6.4 (but not 3.6.5, and not at least
        # some 3.5) would otherwise cancel OSCORE tasks mid-observation. This
        # manifested itself as <https://github.com/chrysn/aiocoap/issues/111>.
        self._tasks = set()

    #
    # implement RequestInterface
    #

    async def fill_or_recognize_remote(self, message):
        if isinstance(message.remote, OSCOREAddress):
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
        if isinstance(secctx, oscore.CanProtect):
            message.remote = OSCOREAddress(secctx, message.remote)
            self.log.debug("Selecting OSCORE transport based on context %r for new request %r", secctx, message)
            return True
        else:
            return False

    def request(self, request):
        t = self.loop.create_task(self._request(request))
        self._tasks.add(t)
        t.add_done_callback(lambda _, _tasks=self._tasks, _t=t: _tasks.remove(_t))

    async def _request(self, request):
        msg = request.request

        secctx = msg.remote.security_context

        def protect(echo):
            if echo is None:
                msg_to_protect = msg
            else:
                if msg.opt.echo:
                    self.log.warning("Overwriting the requested Echo value with the one to answer a 4.01 Unauthorized")
                msg_to_protect = msg.copy(echo=echo)
            protected, original_request_seqno = secctx.protect(msg_to_protect)
            protected.remote = msg.remote.underlying_address

            wire_request = self._wire.request(protected)

            return (wire_request, original_request_seqno)

        wire_request, original_request_seqno = protect(None)

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

            # Offer secctx to switch over for reception based on the header
            # data (similar to how the server address switches over when
            # receiving a response to a request sent over multicast)
            unprotected = oscore.verify_start(protected_response)
            secctx = secctx.context_from_response(unprotected)

            unprotected_response, _ = secctx.unprotect(protected_response, original_request_seqno)

            if unprotected_response.code == UNAUTHORIZED and unprotected_response.opt.echo is not None:
                # Assist the server in B.1.2 Echo receive window recovery
                self.log.info("Answering the server's 4.01 Unauthorized / Echo as part of OSCORE B.1.2 recovery")

                wire_request, original_request_seqno = protect(unprotected_response.opt.echo)

                protected_response = await wire_request.response
                unprotected_response, _ = secctx.unprotect(protected_response, original_request_seqno)

            unprotected_response.remote = OSCOREAddress(secctx, protected_response.remote)
            self.log.debug("Successfully unprotected %r into %r", protected_response, unprotected_response)
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

                more = protected_response.opt.observe is not None
                more = _check(more, unprotected_response)

                unprotected_response.remote = OSCOREAddress(secctx, protected_response.remote)
                self.log.debug("Successfully unprotected %r into %r", protected_response, unprotected_response)
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
