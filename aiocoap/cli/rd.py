# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""A plain CoAP resource directory according to
draft-ietf-core-resource-directory-25

Known Caveats:

    * It is very permissive. Not only is no security implemented.

    * This may and will make exotic choices about discoverable paths whereever
      it can (see StandaloneResourceDirectory documentation)

    * Split-horizon is not implemented correctly

    * Unless enforced by security (ie. not so far), endpoint and sector names
      (ep, d) are not checked for their lengths or other validity.

    * Simple registrations don't cache .well-known/core contents
"""

import string
import sys
import logging
import asyncio
import argparse
from urllib.parse import urljoin
import itertools

import aiocoap
from aiocoap.resource import Site, Resource, ObservableResource, PathCapable, WKCResource, link_format_to_message
from aiocoap.proxy.server import Proxy
from aiocoap.util.cli import AsyncCLIDaemon
import aiocoap.util.uri
from aiocoap import error
from aiocoap.cli.common import add_server_arguments, server_context_from_arguments
from aiocoap.numbers import ContentFormat
import aiocoap.proxy.server

from aiocoap.util.linkformat import Link, LinkFormat, parse
from ..util.asyncio import py38args

import link_header

IMMUTABLE_PARAMETERS = ('ep', 'd', 'proxy')

def query_split(msg):
    """Split a message's query up into (key, [*value]) pairs from a
    ?key=value&key2=value2 style Uri-Query options.

    Keys without an `=` sign will have a None value, and all values are
    expressed as an (at least 1-element) list of repetitions.

    >>> m = aiocoap.Message(uri="coap://example.com/foo?k1=v1.1&k1=v1.2&obs")
    >>> query_split(m)
    {'k1': ['v1.1', 'v1.2'], 'obs': [None]}
    """
    result = {}
    for q in msg.opt.uri_query:
        if '=' not in q:
            k = q
            # matching the representation in link_header
            v = None
        else:
            k, v = q.split('=', 1)
        result.setdefault(k, []).append(v)
    return result

def pop_single_arg(query, name):
    """Out of query which is the output of query_split, pick the single value
    at the key name, raise a suitable BadRequest on error, or return None if
    nothing is there. The value is removed from the query dictionary."""

    if name not in query:
        return None
    if len(query[name]) > 1:
        raise error.BadRequest("Multiple values for %r" % name)
    return query.pop(name)[0]

class CommonRD:
    # "Key" here always means an (ep, d) tuple.

    entity_prefix = ("reg",)

    def __init__(self, proxy_domain=None):
        super().__init__()

        self._by_key = {} # key -> Registration
        self._by_path = {} # path -> Registration

        self._updated_state_cb = []

        self.proxy_domain = proxy_domain
        self.proxy_active = {} # uri_host -> Remote

    class Registration:
        # FIXME: split this into soft and hard grace period (where the former
        # may be 0). the node stays discoverable for the soft grace period, but
        # the registration stays alive for a (possibly much longer, at least
        # +lt) hard grace period, in which any action on the reg resource
        # reactivates it -- preventing premature reuse of the resource URI
        grace_period = 15

        @property
        def href(self):
            return '/' + '/'.join(self.path)

        def __init__(self, static_registration_parameters, path, network_remote, delete_cb, update_cb, registration_parameters, proxy_host, setproxyremote_cb):
            # note that this can not modify d and ep any more, since they are
            # already part of the key and possibly the path
            self.path = path
            self.links = LinkFormat([])

            self._delete_cb = delete_cb
            self._update_cb = update_cb

            self.registration_parameters = static_registration_parameters
            self.lt = 90000
            self.base_is_explicit = False

            self.proxy_host = proxy_host
            self._setproxyremote_cb = setproxyremote_cb

            self.update_params(network_remote, registration_parameters, is_initial=True)

        def update_params(self, network_remote, registration_parameters, is_initial=False):
            """Set the registration_parameters from the parsed query arguments,
            update any effects of them, and and trigger any observation
            observation updates if requried (the typical ones don't because
            their registration_parameters are {} and all it does is restart the
            lifetime counter)"""

            if any(k in ('ep', 'd') for k in registration_parameters.keys()):
                # The ep and d of initial registrations are already popped out
                raise error.BadRequest("Parameters 'd' and 'ep' can not be updated")

            # Not in use class "R" or otherwise conflict with common parameters
            if any(k in ('page', 'count', 'rt', 'href', 'anchor') for k in
                    registration_parameters.keys()):
                raise error.BadRequest("Unsuitable parameter for registration")

            if (is_initial or not self.base_is_explicit) and 'base' not in \
                    registration_parameters:
                # check early for validity to avoid side effects of requests
                # answered with 4.xx
                if self.proxy_host is None:
                    try:
                        network_base = network_remote.uri
                    except error.AnonymousHost:
                        raise error.BadRequest("explicit base required")
                else:
                    # FIXME: Advertise alternative transports (write alternative-transports)
                    network_base = 'coap://' + self.proxy_host

            if is_initial:
                # technically might be a re-registration, but we can't catch that at this point
                actual_change = True
            else:
                actual_change = False

            # Don't act while still checking
            set_lt = None
            set_base = None

            if 'lt' in registration_parameters:
                try:
                    set_lt = int(pop_single_arg(registration_parameters, 'lt'))
                except ValueError:
                    raise error.BadRequest("lt must be numeric")

            if 'base' in registration_parameters:
                set_base = pop_single_arg(registration_parameters, 'base')

            if set_lt is not None and self.lt != set_lt:
                actual_change = True
                self.lt = set_lt
            if set_base is not None and (is_initial or self.base != set_base):
                actual_change = True
                self.base = set_base
                self.base_is_explicit = True

            if not self.base_is_explicit and (is_initial or self.base != network_base):
                self.base = network_base
                actual_change = True

            if any(v != self.registration_parameters.get(k) for (k, v) in registration_parameters.items()):
                self.registration_parameters.update(registration_parameters)
                actual_change = True

            if is_initial:
                self._set_timeout()
            else:
                self.refresh_timeout()

            if actual_change:
                self._update_cb()

            if self.proxy_host:
                self._setproxyremote_cb(network_remote)

        def delete(self):
            self.timeout.cancel()
            self._update_cb()
            self._delete_cb()

        def _set_timeout(self):
            delay = self.lt + self.grace_period
            # workaround for python issue20493

            async def longwait(delay, callback):
                await asyncio.sleep(delay)
                callback()
            self.timeout = asyncio.create_task(
                    longwait(delay, self.delete),
                    **py38args(name="RD Timeout for %r" % self)
                    )

        def refresh_timeout(self):
            self.timeout.cancel()
            self._set_timeout()

        def get_host_link(self):
            attr_pairs = []
            for (k, values) in self.registration_parameters.items():
                for v in values:
                    attr_pairs.append([k, v])
            return Link(href=self.href, attr_pairs=attr_pairs, base=self.base, rt="core.rd-ep")

        def get_based_links(self):
            """Produce a LinkFormat object that represents all statements in
            the registration, resolved to the registration's base (and thus
            suitable for comparing anchors)."""
            result = []
            for l in self.links.links:
                href = urljoin(self.base, l.href)
                if 'anchor' in l:
                    absanchor = urljoin(self.base, l.anchor)
                    data = [(k, v) for (k, v) in l.attr_pairs if k != 'anchor'] + [['anchor', absanchor]]
                else:
                    data = l.attr_pairs + [['anchor', urljoin(href, '/')]]
                result.append(Link(href, data))
            return LinkFormat(result)

    async def shutdown(self):
        pass

    def register_change_callback(self, callback):
        """Ask RD to invoke the callback whenever any of the RD state
        changed"""
        # This has no unregister equivalent as it's only called by the lookup
        # resources that are expected to be live for the remainder of the
        # program, like the Registry is.
        self._updated_state_cb.append(callback)

    def _updated_state(self):
        for cb in self._updated_state_cb:
            cb()

    def _new_pathtail(self):
        for i in itertools.count(1):
            # In the spirit of making legal but unconvential choices (see
            # StandaloneResourceDirectory documentation): Whoever strips or
            # ignores trailing slashes shall have a hard time keeping
            # registrations alive.
            path = (str(i), '')
            if path not in self._by_path:
                return path

    def initialize_endpoint(self, network_remote, registration_parameters):
        # copying around for later use in static, but not checking again
        # because reading them from the original will already have screamed by
        # the time this is used
        static_registration_parameters = {k: v for (k, v) in registration_parameters.items() if k in IMMUTABLE_PARAMETERS}

        ep = pop_single_arg(registration_parameters, 'ep')
        if ep is None:
            raise error.BadRequest("ep argument missing")
        d = pop_single_arg(registration_parameters, 'd')

        proxy = pop_single_arg(registration_parameters, 'proxy')

        if proxy is not None and proxy != 'on':
            raise error.BadRequest("Unsupported proxy value")

        key = (ep, d)

        if static_registration_parameters.pop('proxy', None):
            # FIXME: 'ondemand' is done unconditionally

            if not self.proxy_domain:
                raise error.BadRequest("Proxying not enabled")

            def is_usable(s):
                # Host names per RFC1123 (which is stricter than what RFC3986 would allow).
                #
                # Only supporting lowercase names as to avoid ambiguities due
                # to hostname capitalizatio normalization (otherwise it'd need
                # to be first-registered-first-served)
                return s and all(x in string.ascii_lowercase + string.digits + '-' for x in s)
            if not is_usable(ep) or (d is not None and not is_usable(d)):
                raise error.BadRequest("Proxying only supported for limited ep and d set (lowercase, digits, dash)")

            proxy_host = ep
            if d is not None:
                proxy_host += '.' + d
            proxy_host = proxy_host + '.' + self.proxy_domain
        else:
            proxy_host = None

        # No more errors should fly out from below here, as side effects start now

        try:
            oldreg = self._by_key[key]
        except KeyError:
            path = self._new_pathtail()
        else:
            path = oldreg.path[len(self.entity_prefix):]
            oldreg.delete()

        # this was the brutal way towards idempotency (delete and re-create).
        # if any actions based on that are implemented here, they have yet to
        # decide wheter they'll treat idempotent recreations like deletions or
        # just ignore them unless something otherwise unchangeable (ep, d)
        # changes.

        def delete():
            del self._by_path[path]
            del self._by_key[key]
            self.proxy_active.pop(proxy_host, None)

        def setproxyremote(remote):
            self.proxy_active[proxy_host] = remote

        reg = self.Registration(static_registration_parameters, self.entity_prefix + path, network_remote, delete,
                self._updated_state, registration_parameters, proxy_host, setproxyremote)

        self._by_key[key] = reg
        self._by_path[path] = reg

        return reg

    def get_endpoints(self):
        return self._by_key.values()

def link_format_from_message(message):
    """Convert a response message into a LinkFormat object

    This expects an explicit media type set on the response (or was explicitly requested)
    """
    certain_format = message.opt.content_format
    if certain_format is None:
        certain_format = message.request.opt.accept
    try:
        if certain_format == ContentFormat.LINKFORMAT:
            return parse(message.payload.decode('utf8'))
        else:
            raise error.UnsupportedMediaType()
    except (UnicodeDecodeError, link_header.ParseException):
        raise error.BadRequest()

class ThingWithCommonRD:
    def __init__(self, common_rd):
        super().__init__()
        self.common_rd = common_rd

        if isinstance(self, ObservableResource):
            self.common_rd.register_change_callback(self.updated_state)

class DirectoryResource(ThingWithCommonRD, Resource):
    ct = link_format_to_message.supported_ct
    rt = "core.rd"

    #: Issue a custom warning when registrations come in via this interface
    registration_warning = None

    async def render_post(self, request):
        links = link_format_from_message(request)

        registration_parameters = query_split(request)

        if self.registration_warning:
            # Conveniently placed so it could be changed to something setting
            # additional registration_parameters instead
            logging.warning("Warning from registration: %s", self.registration_warning)

        regresource = self.common_rd.initialize_endpoint(request.remote, registration_parameters)
        regresource.links = links

        return aiocoap.Message(code=aiocoap.CREATED, location_path=regresource.path)

class RegistrationResource(Resource):
    """The resource object wrapping a registration is just a very thin and
    ephemeral object; all those methods could just as well be added to
    Registration with `s/self.reg/self/g`, making RegistrationResource(reg) =
    reg (or handleded in a single RegistrationDispatchSite), but this is kept
    here for better separation of model and interface."""

    def __init__(self, registration):
        super().__init__()
        self.reg = registration

    async def render_get(self, request):
        return link_format_from_message(request, self.reg.links)

    def _update_params(self, msg):
        query = query_split(msg)
        self.reg.update_params(msg.remote, query)

    async def render_post(self, request):
        self._update_params(request)

        if request.opt.content_format is not None or request.payload:
            raise error.BadRequest("Registration update with body not specified")

        return aiocoap.Message(code=aiocoap.CHANGED)

    async def render_put(self, request):
        # this is not mentioned in the current spec, but seems to make sense
        links = link_format_from_message(request)

        self._update_params(request)
        self.reg.links = links

        return aiocoap.Message(code=aiocoap.CHANGED)

    async def render_delete(self, request):
        self.reg.delete()

        return aiocoap.Message(code=aiocoap.DELETED)

class RegistrationDispatchSite(ThingWithCommonRD, Resource, PathCapable):
    async def render(self, request):
        try:
            entity = self.common_rd._by_path[request.opt.uri_path]
        except KeyError:
            raise error.NotFound

        entity = RegistrationResource(entity)

        return await entity.render(request.copy(uri_path=()))

def _paginate(candidates, query):
    page = pop_single_arg(query, 'page')
    count = pop_single_arg(query, 'count')

    try:
        candidates = list(candidates)
        if page is not None:
            candidates = candidates[int(page) * int(count):]
        if count is not None:
            candidates = candidates[:int(count)]
    except (KeyError, ValueError):
        raise error.BadRequest("page requires count, and both must be ints")

    return candidates

def _link_matches(link, key, condition):
    return any(k == key and condition(v) for (k, v) in link.attr_pairs)

class EndpointLookupInterface(ThingWithCommonRD, ObservableResource):
    ct = link_format_to_message.supported_ct
    rt = "core.rd-lookup-ep"

    async def render_get(self, request):
        query = query_split(request)

        candidates = self.common_rd.get_endpoints()

        for search_key, search_values in query.items():
            if search_key in ('page', 'count'):
                continue # filtered last

            for search_value in search_values:
                if search_value is not None and search_value.endswith('*'):
                    def matches(x, start=search_value[:-1]):
                        return x.startswith(start)
                else:
                    def matches(x, search_value=search_value):
                        return x == search_value

                if search_key in ('if', 'rt'):
                    def matches(x, original_matches=matches):
                        return any(original_matches(v) for v in x.split())

                if search_key == 'href':
                    candidates = (c for c in candidates if
                            matches(c.href) or
                            any(matches(r.href) for r in c.get_based_links().links)
                            )
                    continue

                candidates = (c for c in candidates if
                        (search_key in c.registration_parameters and any(matches(x) for x in c.registration_parameters[search_key])) or
                        any(_link_matches(r, search_key, matches) for r in c.get_based_links().links)
                        )

        candidates = _paginate(candidates, query)

        result = [c.get_host_link() for c in candidates]

        return link_format_to_message(request, LinkFormat(result))

class ResourceLookupInterface(ThingWithCommonRD, ObservableResource):
    ct = link_format_to_message.supported_ct
    rt = "core.rd-lookup-res"

    async def render_get(self, request):
        query = query_split(request)

        eps = self.common_rd.get_endpoints()
        candidates = ((e, c) for e in eps for c in e.get_based_links().links)

        for search_key, search_values in query.items():
            if search_key in ('page', 'count'):
                continue # filtered last

            for search_value in search_values:
                if search_value is not None and search_value.endswith('*'):
                    def matches(x, start=search_value[:-1]):
                        return x.startswith(start)
                else:
                    def matches(x, search_value=search_value):
                        return x == search_value

                if search_key in ('if', 'rt'):
                    def matches(x, original_matches=matches):
                        return any(original_matches(v) for v in x.split())

                if search_key == 'href':
                    candidates = ((e, c) for (e, c) in candidates if
                            matches(c.href) or
                            matches(e.href) # FIXME: They SHOULD give this as relative as we do, but don't have to
                            )
                    continue

                candidates = ((e, c) for (e, c) in candidates if
                        _link_matches(c, search_key, matches) or
                        (search_key in e.registration_parameters and any(matches(x) for x in e.registration_parameters[search_key]))
                        )

        # strip endpoint
        candidates = (c for (e, c) in candidates)

        candidates = _paginate(candidates, query)

        # strip needless anchors
        candidates = [
                Link(l.href, [(k, v) for (k, v) in l.attr_pairs if k != 'anchor'])
                if dict(l.attr_pairs)['anchor'] == urljoin(l.href, '/')
                else l
                for l in candidates]

        return link_format_to_message(request, LinkFormat(candidates))

class SimpleRegistration(ThingWithCommonRD, Resource):
    #: Issue a custom warning when registrations come in via this interface
    registration_warning = None

    def __init__(self, common_rd, context):
        super().__init__(common_rd)
        self.context = context

    async def render_post(self, request):
        query = query_split(request)

        if 'base' in query:
            raise error.BadRequest("base is not allowed in simple registrations")

        await self.process_request(
                network_remote=request.remote,
                registration_parameters=query,
            )

        return aiocoap.Message(code=aiocoap.CHANGED)

    async def process_request(self, network_remote, registration_parameters):
        if 'proxy' not in registration_parameters:
            try:
                network_base = network_remote.uri
            except error.AnonymousHost:
                raise error.BadRequest("explicit base required")

            fetch_address = (network_base + '/.well-known/core')
            get = aiocoap.Message(uri=fetch_address)
        else:
            # ignoring that there might be a based present, that will err later
            get = aiocoap.Message(uri_path=['.well-known', 'core'])
            get.remote = network_remote

        get.code = aiocoap.GET
        get.opt.accept = ContentFormat.LINKFORMAT

        # not trying to catch anything here -- the errors are most likely well renderable into the final response
        response = await self.context.request(get).response_raising
        links = link_format_from_message(response)

        if self.registration_warning:
            # Conveniently placed so it could be changed to something setting
            # additional registration_parameters instead
            logging.warning("Warning from registration: %s", self.registration_warning)
        registration = self.common_rd.initialize_endpoint(network_remote, registration_parameters)
        registration.links = links

class SimpleRegistrationWKC(WKCResource, SimpleRegistration):
    def __init__(self, listgenerator, common_rd, context):
        super().__init__(listgenerator=listgenerator, common_rd=common_rd, context=context)
        self.registration_warning = "via .well-known/core"

class StandaloneResourceDirectory(Proxy, Site):
    """A site that contains all function sets of the CoAP Resource Directoru

    To prevent or show ossification of example paths in the specification, all
    function set paths are configurable and default to values that are
    different from the specification (but still recognizable)."""

    rd_path = ("resourcedirectory", "")
    ep_lookup_path = ("endpoint-lookup", "")
    res_lookup_path = ("resource-lookup", "")

    def __init__(self, context, lwm2m_compat=None, **kwargs):
        if lwm2m_compat is True:
            self.rd_path = ("rd",)

        # Double inheritance: works as everything up of Proxy has the same interface
        super().__init__(outgoing_context=context)

        common_rd = CommonRD(**kwargs)

        self.add_resource([".well-known", "core"], SimpleRegistrationWKC(self.get_resources_as_linkheader, common_rd=common_rd, context=context))
        self.add_resource([".well-known", "rd"], SimpleRegistration(common_rd=common_rd, context=context))

        self.add_resource(self.rd_path, DirectoryResource(common_rd=common_rd))
        if list(self.rd_path) != ["rd"] and lwm2m_compat is None:
            second_dir_resource = DirectoryResource(common_rd=common_rd)
            second_dir_resource.registration_warning = "via unannounced /rd"
            # Hide from listing
            second_dir_resource.get_link_description = lambda *args: None
            self.add_resource(["rd"], second_dir_resource)
        self.add_resource(self.ep_lookup_path, EndpointLookupInterface(common_rd=common_rd))
        self.add_resource(self.res_lookup_path, ResourceLookupInterface(common_rd=common_rd))

        self.add_resource(common_rd.entity_prefix, RegistrationDispatchSite(common_rd=common_rd))

        self.common_rd = common_rd

    def apply_redirection(self, request):
        # Fully overriding so we don't need to set an add_redirector

        # infallible as the request only gets here if the proxy path is chosen
        actual_remote = self.common_rd.proxy_active[request.opt.uri_host]
        request.remote = actual_remote
        request.opt.uri_host = None
        return request

    async def shutdown(self):
        await self.common_rd.shutdown()

    async def render(self, request):
        # Full override switching which of the parents' behavior to choose

        if request.opt.uri_host in self.common_rd.proxy_active:
            # This is never the case if proxying is disabled.
            return await Proxy.render(self, request)
        else:
            return await Site.render(self, request)

    # See render; necessary on all functions thanks to https://github.com/chrysn/aiocoap/issues/251

    async def needs_blockwise_assembly(self, request):
        if request.opt.uri_host in self.common_rd.proxy_active:
            return await Proxy.needs_blockwise_assembly(self, request)
        else:
            return await Site.needs_blockwise_assembly(self, request)

    async def add_observation(self, request, serverobservation):
        if request.opt.uri_host in self.common_rd.proxy_active:
            return await Proxy.add_observation(self, request, serverobservation)
        else:
            return await Site.add_observation(self, request, serverobservation)

def build_parser():
    p = argparse.ArgumentParser(description=__doc__)

    add_server_arguments(p)

    return p

class Main(AsyncCLIDaemon):
    async def start(self, args=None):
        parser = build_parser()
        parser.add_argument("--proxy-domain", help="Enable the RD proxy extension. Example: `.proxy.example.net` will produce base URIs like `coap://node1.proxy.example.net/`. The names must all resolve to an address the RD is bound to.", type=str)
        parser.add_argument("--lwm2m-compat", help="Compatibility mode for LwM2M clients that can not perform some discovery steps (moving the registration resource to `/rd`)", action='store_true', default=None)
        parser.add_argument("--no-lwm2m-compat", help="Disable all compativility with LwM2M clients that can not perform some discovery steps (not even accepting registrations at `/rd` with warnings)", action='store_false', dest='lwm2m_compat')
        options = parser.parse_args(args if args is not None else sys.argv[1:])

        # Putting in an empty site to construct the site with a context
        self.context = await server_context_from_arguments(None, options)

        self.site = StandaloneResourceDirectory(context=self.context, proxy_domain=options.proxy_domain, lwm2m_compat=options.lwm2m_compat)
        self.context.serversite = self.site

    async def shutdown(self):
        await self.site.shutdown()
        await self.context.shutdown()

sync_main = Main.sync_main

if __name__ == "__main__":
    sync_main()
