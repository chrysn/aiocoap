# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Basic implementation of CoAP-CoAP proxying

This is work in progress and not yet part of the API."""

import asyncio
import functools
import ipaddress
import logging

from .. import numbers, interfaces, message, error, util

class CanNotRedirect(error.ConstructionRenderableError):
    message = "Proxy redirection failed"

class NoUriSplitting(CanNotRedirect):
    code = numbers.codes.NOT_IMPLEMENTED
    message = "URI splitting not implemented, please use Proxy-Scheme."

class IncompleteProxyUri(CanNotRedirect):
    code = numbers.codes.BAD_REQUEST
    message = "Proxying requires Proxy-Scheme and Uri-Host"

class NotAForwardProxy(CanNotRedirect):
    code = numbers.codes.PROXYING_NOT_SUPPORTED
    message = "This is a reverse proxy, not a forward one."

class NoSuchHostname(CanNotRedirect):
    code = numbers.codes.NOT_FOUND
    message = ""

class CanNotRedirectBecauseOfUnsafeOptions(CanNotRedirect):
    code = numbers.codes.BAD_OPTION

    def __init__(self, options):
        self.message = "Unsafe options in request: %s"%(", ".join(str(o.number) for o in options))

def raise_unless_safe(request, known_options):
    """Raise a BAD_OPTION CanNotRedirect unless all options in request are
    safe to forward or known"""

    known_options = set(known_options).union({
        # it is expected that every proxy is aware of these options even though
        # one of them often doesn't need touching
        numbers.OptionNumber.URI_HOST,
        numbers.OptionNumber.URI_PORT,
        numbers.OptionNumber.URI_PATH,
        numbers.OptionNumber.URI_QUERY,
        # handled by the Context
        numbers.OptionNumber.BLOCK1,
        numbers.OptionNumber.BLOCK2,
        # handled by the proxy resource
        numbers.OptionNumber.OBSERVE,
        })

    unsafe_options = [o for o in request.opt.option_list() if o.number.is_unsafe() and o.number not in known_options]
    if unsafe_options:
        raise CanNotRedirectBecauseOfUnsafeOptions(unsafe_options)

class Proxy(interfaces.Resource):
    # other than in special cases, we're trying to be transparent wrt blockwise transfers
    interpret_block_options = False

    def __init__(self, outgoing_context, logger=None):
        super().__init__()
        self.outgoing_context = outgoing_context
        self.log = logger or logging.getLogger('proxy')

        self._redirectors = []

    def add_redirector(self, redirector):
        self._redirectors.append(redirector)

    def apply_redirection(self, request):
        for r in self._redirectors:
            result = r.apply_redirection(request)
            if result is not None:
                return result
        return None

    async def needs_blockwise_assembly(self, request):
        return self.interpret_block_options

    async def render(self, request):
        # FIXME i'd rather let the application do with the message whatever it
        # wants. everything the responder needs of the request should be
        # extracted beforehand.
        request = request.copy(mid=None, token=None)

        try:
            request = self.apply_redirection(request)
        except CanNotRedirect as e:
            return e.to_message()

        if request is None:
            response = await super().render(request)
            if response is None:
                raise IncompleteProxyUri("No matching proxy rule")
            return response

        try:
            response = await self.outgoing_context.request(request, handle_blockwise=self.interpret_block_options).response
        except error.RequestTimedOut as e:
            return message.Message(code=numbers.codes.GATEWAY_TIMEOUT)

        raise_unless_safe(response, ())

        response.mtype = None
        response.mid = None
        response.remote = None
        response.token = None

        return response

class ProxyWithPooledObservations(Proxy, interfaces.ObservableResource):
    def __init__(self, outgoing_context, logger=None):
        super(ProxyWithPooledObservations, self).__init__(outgoing_context, logger)

        self._outgoing_observations = {}

    @staticmethod
    def _cache_key(request):
        return request.get_cache_key([numbers.optionnumbers.OptionNumber.OBSERVE])

    def _peek_observation_for(self, request):
        """Return the augmented request (see _get_obervation_for) towards a
        resource, or raise KeyError"""
        cachekey = self._cache_key(request)

        return self._outgoing_observations[cachekey]

    def _get_observation_for(self, request):
        """Return an existing augmented request towards a resource or create one.

        An augmented request is an observation request that has some additional
        properties (__users, __cachekey, __latest_response), which are used in
        ProxyWithPooledObservations to immediately serve responses from
        observed resources, and to tear the observations down again."""

        # see ProxiedResource.render
        request = request.copy(mid=None, remote=None, token=None)
        request = self.apply_redirection(request)

        cachekey = self._cache_key(request)

        try:
            obs = self._outgoing_observations[cachekey]
        except KeyError:
            obs = self._outgoing_observations[cachekey] = self.outgoing_context.request(request)
            obs.__users = set()
            obs.__cachekey = cachekey
            obs.__latest_response = None # this becomes a cached response right after the .response comes in (so only use this after waiting for it), and gets updated when new responses arrive.

            def when_first_request_done(result, obs=obs):
                obs.__latest_response = result.result()
            obs.response.add_done_callback(when_first_request_done)

            def cb(incoming_message, obs=obs):
                self.log.info("Received incoming message %r, relaying it to %d clients", incoming_message, len(obs.__users))
                obs.__latest_response = incoming_message
                for observationserver in set(obs.__users):
                    observationserver.trigger(incoming_message.copy())
            obs.observation.register_callback(cb)
            def eb(exception, obs=obs):
                if obs.__users:
                    code = numbers.codes.INTERNAL_SERVER_ERROR
                    payload = b""
                    if isinstance(exception, error.RenderableError):
                        code = exception.code
                        payload = exception.message.encode('ascii')
                    self.log.debug("Received error %r, which did not lead to unregistration of the clients. Actively deregistering them with %s %r.", exception, code, payload)
                    for u in list(obs.__users):
                        u.trigger(message.Message(code=code, payload=payload))
                    if obs.__users:
                        self.log.error("Observations survived sending them an error message.")
                else:
                    self.log.debug("Received error %r, but that seems to have been passed on cleanly to the observers as they are gone by now.", exception)
            obs.observation.register_errback(eb)

        return obs

    def _add_observation_user(self, clientobservationrequest, serverobservation):
        clientobservationrequest.__users.add(serverobservation)

    def _remove_observation_user(self, clientobservationrequest, serverobservation):
        clientobservationrequest.__users.remove(serverobservation)
        # give the request that just cancelled time to be dealt with before
        # dropping the __latest_response
        asyncio.get_event_loop().call_soon(self._consider_dropping, clientobservationrequest)

    def _consider_dropping(self, clientobservationrequest):
        if not clientobservationrequest.__users:
            self.log.debug("Last client of observation went away, deregistering with server.")
            self._outgoing_observations.pop(clientobservationrequest.__cachekey)
            if not clientobservationrequest.observation.cancelled:
                clientobservationrequest.observation.cancel()

    async def add_observation(self, request, serverobservation):
        """As ProxiedResource is intended to be just the proxy's interface
        toward the Context, accepting observations is handled here, where the
        observations handling can be defined by the subclasses."""

        try:
            clientobservationrequest = self._get_observation_for(request)
        except CanNotRedirect:
            pass # just don't accept the observation, the rest will be taken care of at rendering
        else:
            self._add_observation_user(clientobservationrequest, serverobservation)
            serverobservation.accept(functools.partial(self._remove_observation_user, clientobservationrequest, serverobservation))

    async def render(self, request):
        # FIXME this is evaulated twice in the implementation (once here, but
        # unless it's an observation what matters is inside the super call),
        # maybe this needs to hook in differently than by subclassing and
        # calling super.
        self.log.info("render called")
        redirected_request = request.copy()

        try:
            redirected_request = self.apply_redirection(redirected_request)
            if redirected_request is None:
                return await super().render(request)
            clientobservationrequest = self._peek_observation_for(redirected_request)
        except (KeyError, CanNotRedirect) as e:
            if not isinstance(e, CanNotRedirect) and request.opt.observe is not None:
                self.log.warning("No matching observation found: request is %r (cache key %r), outgoing observations %r", redirected_request, self._cache_key(redirected_request), self._outgoing_observations)

                return message.Message(code=numbers.codes.BAD_OPTION, payload="Observe option can not be proxied without active observation.".encode('utf8'))
            self.log.debug("Request is not an observation or can't be proxied, passing it on to regular proxying mechanisms.")
            return await super(ProxyWithPooledObservations, self).render(request)
        else:
            self.log.info("Serving request using latest cached response of %r", clientobservationrequest)
            await clientobservationrequest.response
            cached_response = clientobservationrequest.__latest_response
            cached_response.mid = None
            cached_response.token = None
            cached_response.remote = None
            cached_response.mtype = None
            return cached_response


class ForwardProxy(Proxy):
    def apply_redirection(self, request):
        request = request.copy()
        if request.opt.proxy_uri is not None:
            raise NoUriSplitting
        if request.opt.proxy_scheme is None:
            return super().apply_redirection(request)
        if request.opt.uri_host is None:
            raise IncompleteProxyUri

        raise_unless_safe(request, (numbers.OptionNumber.PROXY_SCHEME, numbers.OptionNumber.URI_HOST, numbers.OptionNumber.URI_PORT))

        request.remote = message.UndecidedRemote(request.opt.proxy_scheme, util.hostportjoin(request.opt.uri_host, request.opt.uri_port))
        request.opt.proxy_scheme = None
        request.opt.uri_port = None
        try:
            # I'd prefer to not do if-by-try, but the ipaddress doesn't seem to
            # offer any other choice
            ipaddress.ip_address(request.opt.uri_host)
        except ValueError:
            pass
        else:
            request.opt.uri_host = None
        if request.opt.uri_host.startswith('['):
            # IPv6 or future literals are not recognized by ipaddress which
            # does not look at host-encoded form
            request.opt.uri_host = None

        # Maybe the URI-Host matches a known forwarding -- in that case, catch that.
        redirected = super(ForwardProxy, self).apply_redirection(request)
        if redirected is not None:
            return redirected

        return request

class ForwardProxyWithPooledObservations(ForwardProxy, ProxyWithPooledObservations):
    pass

class ReverseProxy(Proxy):
    def __init__(self, *args, **kwargs):
        import warnings
        warnings.warn("ReverseProxy has become moot due to proxy operation "
                "changes, just instanciate Proxy and set the appropriate "
                "redirectors", DeprecationWarning, stacklevel=1)
        super().__init__(*args, **kwargs)

class ReverseProxyWithPooledObservations(ReverseProxy, ProxyWithPooledObservations):
    pass

class Redirector():
    def apply_redirection(self, request):
        return None

class NameBasedVirtualHost(Redirector):
    def __init__(self, match_name, target, rewrite_uri_host=False, use_as_proxy=False):
        self.match_name = match_name
        self.target = target
        self.rewrite_uri_host = rewrite_uri_host
        self.use_as_proxy = use_as_proxy

    def apply_redirection(self, request):
        raise_unless_safe(request, ())

        if self._matches(request.opt.uri_host):
            if self.use_as_proxy:
                request.opt.proxy_scheme = request.remote.scheme
            if self.rewrite_uri_host:
                request.opt.uri_host, _ = util.hostportsplit(self.target)
            request.unresolved_remote = self.target
            return request

    def _matches(self, hostname):
        return hostname == self.match_name

class SubdomainVirtualHost(NameBasedVirtualHost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.rewrite_uri_host:
            raise TypeError("rewrite_uri_host makes no sense with subdomain virtual hosting")

    def _matches(self, hostname):
        return hostname.endswith('.' + self.match_name)

class UnconditionalRedirector(Redirector):
    def __init__(self, target, use_as_proxy=False):
        self.target = target
        self.use_as_proxy= use_as_proxy

    def apply_redirection(self, request):
        raise_unless_safe(request, ())

        if self.use_as_proxy:
            request.opt.proxy_scheme = request.remote.scheme
        request.unresolved_remote = self.target
        return request

class SubresourceVirtualHost(Redirector):
    def __init__(self, path, target):
        self.path = tuple(path)
        self.target = target

    def apply_redirection(self, request):
        raise_unless_safe(request, ())

        if self.path == request.opt.uri_path[:len(self.path)]:
            request.opt.uri_path = request.opt.uri_path[len(self.path):]
            request.unresolved_remote = self.target
            return request
