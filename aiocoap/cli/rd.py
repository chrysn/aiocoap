# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""A plain CoAP resource directory according to
draft-ietf-core-resource-directory-14

Known Caveats:

    * Nothing group related is implemented.

    * Multiply given registration parameters are not handled.

    * It is very permissive. Not only is no security implemented.
"""

import sys
import logging
import asyncio
import argparse
from urllib.parse import urljoin
import itertools

import aiocoap
from aiocoap.resource import Site, Resource, ObservableResource, PathCapable, WKCResource, link_format_to_message
from aiocoap.util.cli import AsyncCLIDaemon
from aiocoap import error
from aiocoap.cli.common import add_server_arguments, server_context_from_arguments
from aiocoap.numbers import media_types_rev

from aiocoap.util.linkformat import Link, LinkFormat, parse

import link_header

def query_split(msg):
    return dict(q.split('=', 1) if '=' in q else (q, True) for q in msg.opt.uri_query)

class CommonRD:
    # the `key` of an endpoint is not really worked out yet. currently it's
    # (ep, d) 2-tuples; code that handles key internals should be limited to
    # this class.

    entity_prefix = ("reg",)

    def __init__(self):
        super().__init__()

        self._endpoint_registrations_by_key = {} # key -> Registration
        self._entities_by_pathtail = {} # path -> Registration or Group

        self._updated_state_cb = []

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

        def __init__(self, path, network_remote, delete_cb, update_cb, registration_parameters):
            # note that this can not modify d and ep any more, since they were
            # already used in keying to a path
            self.path = path
            self.links = LinkFormat([])

            self._delete_cb = delete_cb
            self._update_cb = update_cb
            self.update_params(network_remote, registration_parameters, is_initial=True)

        def update_params(self, network_remote, registration_parameters, is_initial=False):
            """Set the registration_parameters from the parsed query arguments,
            update any effects of them, and and trigger any observation
            observation updates if requried (the typical ones don't because
            their registration_parameters are {} and all it does is restart the
            lifetime counter)"""

            if (is_initial or not self.base_is_explicit) and 'base' not in \
                    registration_parameters:
                # check early for validity to avoid side effects of requests
                # answered with 4.xx
                try:
                    network_base = network_remote.uri
                except error.AnonymousHost:
                    raise error.BadRequest("explicit base required")

            if is_initial:
                self.registration_parameters = registration_parameters
                self.lt = 90000
                if 'base' not in registration_parameters:
                    self.base = network_base
                    self.base_is_explicit = False

                # technically might be a re-registration, but we can't catch that at this point
                actual_change = True
            else:
                if 'd' in registration_parameters or 'ep' in registration_parameters:
                    raise error.BadRequest("Parameters 'd' and 'ep' can not be updated")

                actual_change = any(v != self.registration_parameters.get(k, -1) for (k, v) in registration_parameters.items())

                self.registration_parameters = dict(self.registration_parameters, **registration_parameters)

            if 'lt' in registration_parameters:
                try:
                    self.lt = int(registration_parameters['lt'])
                except ValueError:
                    raise error.BadRequest("lt must be numeric")

            if 'base' in registration_parameters:
                self.base = registration_parameters['base']
                self.base_is_explicit = True

            if not self.base_is_explicit and self.base != network_base:
                self.base = network_base
                actual_change = True

            if is_initial:
                self._set_timeout()
            else:
                self.refresh_timeout()

            if actual_change:
                self._update_cb()

        def delete(self):
            self.timeout.cancel()
            self._update_cb()
            self._delete_cb()

        def _set_timeout(self):
            delay = self.lt + self.grace_period
            # workaround for python issue20493

            async def longwait(delay, callback):
                almostday = 24*60*60 - 10
                while delay > almostday:
                    await asyncio.sleep(almostday)
                    delay -= almostday
                await asyncio.sleep(delay)
                callback()
            self.timeout = asyncio.Task(longwait(delay, self.delete))

        def refresh_timeout(self):
            self.timeout.cancel()
            self._set_timeout()

        def get_host_link(self):
            args = dict(self.registration_parameters, base=self.base, rt="core.rd-ep")
            args.pop('lt', None)
            return Link(href=self.href, **args)

        def get_based_links(self):
            """Produce a LinkFormat object that represents all statements in
            the registration, resolved to the registration's base (and thus
            suitable for serving from the lookup interface).

            This implements Modernized Link Format as described in Appendix D
            of draft-ietf-core-resource-directory-15.

            If protocol negotiation is implemented and base becomes a list, this
            function will probably grow parameters that hint at which base to
            use.
            """
            result = []
            for l in self.links.links:
                if 'anchor' in l:
                    absanchor = urljoin(self.base, l.anchor)
                    data = [(k, v) for (k, v) in l.attr_pairs if k != 'anchor'] + [['anchor', absanchor]]
                else:
                    data = l.attr_pairs + [['anchor', self.base]]
                href = urljoin(self.base, l.href)
                result.append(Link(href, data))
            return LinkFormat(result)

    async def shutdown(self):
        pass

    def register_change_callback(self, callback):
        """Ask RD to invoke the callback whenever any of the RD state
        changed"""
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
            if path not in self._entities_by_pathtail:
                return path

    def initialize_endpoint(self, network_remote, registration_parameters):
        try:
            ep = registration_parameters['ep']
        except KeyError:
            raise error.BadRequest("ep argument missing")
        d = registration_parameters.get('d', None)

        key = (ep, d)

        try:
            oldreg = self._endpoint_registrations_by_key[key]
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
            del self._entities_by_pathtail[path]
            del self._endpoint_registrations_by_key[key]

        reg = self.Registration(self.entity_prefix + path, network_remote, delete,
                self._updated_state, registration_parameters)

        self._endpoint_registrations_by_key[key] = reg
        self._entities_by_pathtail[path] = reg

        return reg

    def get_endpoints(self):
        return self._endpoint_registrations_by_key.values()

def link_format_from_message(message):
    try:
        if message.opt.content_format == media_types_rev['application/link-format']:
            return parse(message.payload.decode('utf8'))
        elif message.opt.content_format == media_types_rev['application/link-format+json']:
            return LinkFormat.from_json_string(message.payload.decode('utf8'))
        elif message.opt.content_format == media_types_rev['application/link-format+cbor']:
            return LinkFormat.from_cbor_bytes(message.payload)
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

class RegistrationInterface(ThingWithCommonRD, Resource):
    ct = link_format_to_message.supported_ct
    rt = "core.rd"

    async def render_post(self, request):
        links = link_format_from_message(request)

        registration_parameters = query_split(request)

        regresource = self.common_rd.initialize_endpoint(request.remote, registration_parameters)
        regresource.links = links

        return aiocoap.Message(code=aiocoap.CREATED, location_path=regresource.path)

class RegistrationResource(Resource):
    """The resource object wrapping a registration is just a very thin and
    ephemeral object; all those methods could just as well be added to
    Registration with `s/self.reg/self/g`, making RegistrationResource(reg) =
    reg, but this is kept here for better separation of model and interface."""

    def __init__(self, registration):
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

class EntityDispatchSite(ThingWithCommonRD, Resource, PathCapable):
    async def render(self, request):
        try:
            entity = self.common_rd._entities_by_pathtail[request.opt.uri_path]
        except KeyError:
            raise error.NotFound

        if isinstance(entity, CommonRD.Registration):
            entity = RegistrationResource(entity)
        else:
            raise ValueError("Unexpected object in entities")

        return await entity.render(request.copy(uri_path=()))

def _paginate(candidates, query):
    try:
        candidates = list(candidates)
        if 'page' in query:
            candidates = candidates[int(query['page']) * int(query['count']):]
        if 'count' in query:
            candidates = candidates[:int(query['count'])]
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

        for search_key, search_value in query.items():
            if search_key in ('page', 'count'):
                continue # filtered last

            if search_value.endswith('*'):
                matches = lambda x, start=search_value[:-1]: x.startswith(start)
            else:
                matches = lambda x: x == search_value

            if search_key in ('if', 'rt'):
                candidates = (c for c in candidates if any(any(matches(x) for x in ' '.join(getattr(r, search_key, '')).split()) for r in c.get_based_links().links))
                continue

            if search_key == 'href':
                candidates = (c for c in candidates if
                        matches(c.href) or
                        any(matches(r.href) for r in c.get_based_links().links)
                        )
                continue

            candidates = (c for c in candidates if
                    (search_key in c.registration_parameters and matches(c.registration_parameters[search_key])) or
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

        for search_key, search_value in query.items():
            if search_key in ('page', 'count'):
                continue # filtered last

            # FIXME: maybe we need query_split to turn ?rt=foo&obs into {'rt':
            # 'foo', 'obs': True} to match on obs, and then this needs more
            # type checking
            if search_value.endswith('*'):
                matches = lambda x, start=search_value[:-1]: x.startswith(start)
            else:
                matches = lambda x: x == search_value

            if search_key in ('if', 'rt'):
                candidates = ((e, c) for (e, c) in candidates if any(matches(x) for x in " ".join(getattr(c, search_key, ())).split()))
                continue

            if search_key == 'href':
                candidates = ((e, c) for (e, c) in candidates if
                        matches(urljoin(e.base, c.href)) or
                        matches(e.href) # FIXME: actually resolved e, but so far we've avoided knowing our own
                        )
                continue

            candidates = ((e, c) for (e, c) in candidates if
                    _link_matches(c, search_key, matches) or
                    (search_key in e.registration_parameters and matches(e.registration_parameters[search_key]))
                    )

        # strip endpoint
        candidates = (c for (e, c) in candidates)

        candidates = _paginate(candidates, query)

        return link_format_to_message(request, LinkFormat(candidates))

class SimpleRegistrationWKC(WKCResource):
    def __init__(self, listgenerator, common_rd):
        super().__init__(listgenerator)
        self.common_rd = common_rd

    async def render_post(self, request):
        query = query_split(request)

        # this is not deduplicated with update_params in full because that code
        # path is triggered later when the response was already sent

        if 'ep' not in query:
            raise error.BadRequest("ep argument missing")

        if 'lt' in query:
            try:
                # just trying out whether it can be constructed to err out
                # early and meaningfully
                int(query['lt'])
            except ValueError:
                raise error.BadRequest("lt must be numeric")

        if 'base' in query:
            raise error.BadRequest("base is not allowed in simple registrations")

        try:
            # just trying out whether it can be constructed to err out in
            # time (under the current model of "respond early, ask later")
            request.remote.uri
        except error.UnparsableMessage:
            raise error.BadRequest("explicit base required")

        asyncio.Task(self.process_request(
                network_remote=request.remote,
                registration_parameters=query,
            ))

        return aiocoap.Message(code=aiocoap.CHANGED)

    async def process_request(self, network_remote, registration_parameters):
        base = network_remote.uri

        fetch_address = (base + '/.well-known/core')

        try:
            response = await self.context.request(aiocoap.Message(code=aiocoap.GET, uri=fetch_address)).response_raising
            links = link_format_from_message(response)
        except Exception as e:
            logging.error("The request triggered for simple registration of %s failed.", base)
            logging.exception(e)
            return

        registration = self.common_rd.initialize_endpoint(network_remote, registration_parameters)
        registration.links = links

class StandaloneResourceDirectory(Site):
    """A site that contains all function sets of the CoAP Resource Directoru

    To prevent or show ossification of example paths in the specification, all
    function set paths are configurable and default to values that are
    different from the specification (but still recognizable)."""

    rd_path = ("resourcedirectory",)
    ep_lookup_path = ("endpoint-lookup",)
    res_lookup_path = ("resource-lookup",)

    def __init__(self):
        super().__init__()

        common_rd = CommonRD()

        self._simple_wkc = SimpleRegistrationWKC(self.get_resources_as_linkheader, common_rd=common_rd)
        self.add_resource([".well-known", "core"], self._simple_wkc)

        self.add_resource(self.rd_path, RegistrationInterface(common_rd=common_rd))
        self.add_resource(self.ep_lookup_path, EndpointLookupInterface(common_rd=common_rd))
        self.add_resource(self.res_lookup_path, ResourceLookupInterface(common_rd=common_rd))

        self.add_resource(common_rd.entity_prefix, EntityDispatchSite(common_rd=common_rd))

        self.common_rd = common_rd

    async def shutdown(self):
        await self.common_rd.shutdown()

    # the need to pass this around crudely demonstrates that the setup of sites
    # and contexts direly needs improvement, and thread locals are giggling
    # about my stubbornness
    def set_context(self, new_context):
        self._simple_wkc.context = new_context

def build_parser():
    p = argparse.ArgumentParser(description=__doc__)

    add_server_arguments(p)

    return p

class Main(AsyncCLIDaemon):
    async def start(self, args=None):
        parser = build_parser()
        options = parser.parse_args(args if args is not None else sys.argv[1:])

        self.site = StandaloneResourceDirectory()

        self.context = await server_context_from_arguments(self.site, options)
        self.site.set_context(self.context)

    async def shutdown(self):
        await self.site.shutdown()
        await self.context.shutdown()

sync_main = Main.sync_main

if __name__ == "__main__":
    sync_main()
