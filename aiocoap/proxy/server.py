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
import copy
import urllib.parse
import functools

from .. import numbers, interfaces, message, error

class CanNotRedirect(Exception):
    def __init__(self, code, explanation):
        super(CanNotRedirect, self).__init__()
        self.code = code
        self.explanation = explanation

class CanNotRedirectBecauseOfUnsafeOptions(CanNotRedirect):
    def __init__(self, options):
        self.code = numbers.codes.BAD_OPTION
        self.explanation = "Unsafe options in request: %s"%(", ".join(str(o.number) for o in options))
        self.options = options

def raise_unless_safe(request, known_options):
    """Raise a BAD_OPTION CanNotRedirect unless all options in request are
    safe to forward or known"""

    known_options = set(known_options).union({
        # it is expected that every proxy is aware of these options even though
        # one of them often doesn't need touching
        numbers.OptionNumber.URI_HOST,
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

class Proxy():
    # other than in special cases, we're trying to be transparent wrt blockwise transfers
    interpret_block_options = False

    def __init__(self, outgoing_context):
        self.outgoing_context = outgoing_context

        self._redirectors = []

    def add_redirector(self, redirector):
        self._redirectors.append(redirector)

    def apply_redirection(self, request):
        for r in self._redirectors:
            result = r.apply_redirection(request)
            if result is not None:
                return result
        return None

class ProxyWithPooledObservations(Proxy):
    def __init__(self, outgoing_context):
        super(ProxyWithPooledObservations, self).__init__(outgoing_context)

        self._outgoing_observations = {}

    @staticmethod
    def _cache_key(request):
        return request.get_cache_key([numbers.optionnumbers.OptionNumber.OBSERVE])

    def _get_observation_for(self, request):
        cachekey = self._cache_key(request)

        try:
            obs = self._outgoing_observations[cachekey]
        except KeyError:
            # not sure if absolutely required, but we have a similar thing in
            # ProxiedResource.render for reasons.
            request = copy.copy(request)

            request.mid = None
            request.remote = None
            request.token = None

            obs = self._outgoing_observations[cachekey] = self.outgoing_context.request(request)
            obs.__users = set()
            obs.__cachekey = cachekey
            obs.__latest_response = asyncio.Future()

        return obs

    def _add_observation_user(self, clientobservationrequest, serverobservation):
        clientobservationrequest.__users.add(serverobservation)

    def _remove_observation_user(self, clientobservationrequest, serverobservation):
        clientobservationrequest.__users.remove(serverobservation)
        if not clientobservationrequest.__users:
            self._outgoing_observations.pop(clientobservationrequest.__cachekey)
            clientobservationrequest.observation.cancel()

    @asyncio.coroutine
    def add_observation(self, request, serverobservation):
        """As ProxiedResource is intended to be just the proxy's interface
        toward the Context, accepting observations is handled here, where the
        observations handling can be defined by the subclasses."""

        clientobservationrequest = self._get_observation_for(request)

        self._add_observation_user(clientobservationrequest, serverobservation)
        serverobservation.accept(functools.partial(self._remove_observation_user, clientobservationrequest, serverobservation))

        clientobservationrequest.observation.register_callback(lambda incoming_message: serverobservation.trigger(copy.copy(incoming_message)))

class ForwardProxy(Proxy):
    def apply_redirection(self, request):
        if request.opt.proxy_uri is not None:
            raise CanNotRedirect(numbers.codes.NOT_IMPLEMENTED, "URI splitting not implemented, please use Proxy-Scheme.")
        if request.opt.proxy_scheme is None:
            raise CanNotRedirect(numbers.codes.BAD_REQUEST, "This is only a proxy.") # correct error code?
        if request.opt.proxy_scheme != 'coap':
            raise CanNotRedirect(numbers.codes.BAD_OPTION, "This is only a CoAP proxy (set uri-scheme to coap)")

        request.opt.proxy_scheme = None

        redirected = super(ForwardProxy, self).apply_redirection(request)
        if redirected is not None:
            return redirected

        raise_unless_safe(request, (numbers.OptionNumber.PROXY_SCHEME, numbers.OptionNumber.URI_HOST))

        return request

class ForwardProxyWithPooledObservations(ForwardProxy, ProxyWithPooledObservations):
    pass

class ReverseProxy(Proxy):
    def apply_redirection(self, request):
        if request.opt.proxy_uri is not None or request.opt.proxy_scheme is not None:
            # that should somehow be default...
            raise CanNotRedirect(numbers.codes.PROXYING_NOT_SUPPORTED, "This is a reverse proxy, not a forward one.")

        redirected = super(ReverseProxy, self).apply_redirection(request)
        if redirected is None:
            raise CanNotRedirect(numbers.codes.NOT_FOUND, "")

        return redirected

class ReverseProxyWithPooledObservations(ReverseProxy, ProxyWithPooledObservations):
    pass

class Redirector():
    def apply_redirection(self, request):
        return None

def splitport(hostport):
    """Like urllib.parse.splitport, but return port as int, and as None if it
    equals the CoAP default port. Also, it allows giving IPv6 addresses like a netloc:

    >>> splitport('foo')
    ('foo', None)
    >>> splitport('foo:5683')
    ('foo', None)
    >>> splitport('[::1]:56830')
    ('::1', 56830)
    """

    pseudoparsed = urllib.parse.SplitResult(None, hostport, None, None, None)
    host, port = pseudoparsed.hostname, pseudoparsed.port
    if port == numbers.constants.COAP_PORT:
        port = None
    return host, port

class NameBasedVirtualHost(Redirector):
    def __init__(self, match_name, target, rewrite_uri_host=False):
        self.match_name = match_name
        self.target = target
        self.rewrite_uri_host = rewrite_uri_host

    def apply_redirection(self, request):
        raise_unless_safe(request, ())

        if request.opt.uri_host == self.match_name:
            if self.rewrite_uri_host:
                request.opt.uri_host, request.opt.uri_port = splitport(self.target)
            else:
                request.unresolved_remote = self.target
            return request

class UnconditionalRedirector(Redirector):
    def __init__(self, target):
        self.target = target

    def apply_redirection(self, request):
        raise_unless_safe(request, ())

        request.unresolved_remote = target
        return request

class SubresourceVirtualHost(Redirector):
    def __init__(self, path, target):
        self.path = tuple(path)
        self.target = target

    def apply_redirection(self, request):
        raise_unless_safe(request, ())

        if self.path == request.opt.uri_path[:len(self.path)]:
            request.opt.uri_path = request.opt.uri_path[len(self.path):]
            request.opt.uri_host, request.opt.uri_port = splitport(self.target)
            return request

class ProxiedResource(interfaces.ObservableResource):
    def __init__(self, proxy):
        self.proxy = proxy


    @asyncio.coroutine
    def needs_blockwise_assembly(self, request):
        return self.proxy.interpret_block_options

    @asyncio.coroutine
    def render(self, request):
        # FIXME i'd rather let the application do with the message whatever it
        # wants. everything the responder needs of the request should be
        # extracted beforehand.
        request = copy.copy(request)

        request.mid = None
        request.remote = None
        request.token = None

        try:
            request = self.proxy.apply_redirection(request)
        except CanNotRedirect as e:
            return message.Message(code=e.code, payload=e.explanation.encode('utf8'))

        try:
            response = yield from self.proxy.outgoing_context.request(request, handle_blockwise=self.proxy.interpret_block_options).response
        except error.RequestTimedOut as e:
            return message.Message(code=numbers.codes.GATEWAY_TIMEOUT)

        raise_unless_safe(response, ())

        response.mtype = None
        response.mid = None
        response.remote = None
        response.token = None

        return response

    @asyncio.coroutine
    def add_observation(self, request, serverobservation):
        if hasattr(self.proxy, "add_observation"):
            yield from self.proxy.add_observation(request, serverobservation)
