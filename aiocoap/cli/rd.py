# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""a plain CoAP resource directory according to
draft-ietf-core-resource-directory-09"""

import sys
import logging
import asyncio
import argparse
import functools
from urllib.parse import urljoin
import itertools

import aiocoap
from aiocoap.resource import Site, Resource, PathCapable, WKCResource
from aiocoap.util.cli import AsyncCLIDaemon
from aiocoap import error

import link_header
from link_header import Link, LinkHeader

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

    class Registration:
        grace_period = 15

        @property
        def href(self):
            return '/' + '/'.join(self.path)

        def __init__(self, path, con, delete_cb, ep, d=None, lt=None, et=None):
            self.path = path
            self.links = LinkHeader([])
            self.ep = ep
            self.d = d
            self.lt = lt or 86400
            self.et = et
            self.con = con

            self._delete_cb = delete_cb
            self._set_timeout()

        def delete(self):
            self.timeout.cancel()
            self._delete_cb()

        def _set_timeout(self):
            delay = self.lt + self.grace_period
            # workaround for python issue20493

            @asyncio.coroutine
            def longwait(delay, callback):
                almostday = 24*60*60 - 10
                while delay > almostday:
                    yield from asyncio.sleep(almostday)
                    delay -= almostday
                yield from asyncio.sleep(delay)
                callback()
            self.timeout = asyncio.Task(longwait(delay, self.delete))

        def refresh_timeout(self):
            self.timeout.cancel()
            self._set_timeout()

        def get_host_link(self):
            args = {'ep': self.ep}
            if self.d:
                args['d'] = self.d
            if self.et:
                args['et'] = self.et
            args['con'] = self.con
            return Link(href=self.href, **args)

        def get_conned_links(self):
            """Produce a LinkHeader object that represents all statements in
            the registration, resolved to the registration's con (and thus
            suitable for serving from the lookup interface).

            If protocol negotiation is implemented and con becomes a list, this
            function will probably grow parameters that hint at which con to
            use.
            """
            result = []
            for l in self.links.links:
                if 'anchor' in l:
                    data = [(k, v) for (k, v) in l.attr_pairs if k != 'anchor'] + [['anchor', urljoin(self.con, l.anchor)]]
                else:
                    data = l.attr_pairs + [['anchor', self.con]]
                result.append(Link(l.href, data))
            return LinkHeader(result)

    @asyncio.coroutine
    def shutdown(self):
        pass

    def _new_pathtail(self):
        for i in itertools.count(1):
            # In the spirit of making legal but unconvential choices (see
            # StandaloneResourceDirectory documentation): Whoever strips or
            # ignores trailing slashes shall have a hard time keeping
            # registrations alive.
            path = (str(i), '')
            if path not in self._entities_by_pathtail:
                return path

    def initialize_endpoint(self, con, ep, lt=None, et=None, d=None):
        # FIXME: It's a bit unclear if the specification actually requires the
        # idempotency of registration on (ep, d) or any other parameters
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

        reg = self.Registration(self.entity_prefix + path, con=con, delete_cb=delete, ep=ep, lt=lt,
                et=et, d=d)

        self._endpoint_registrations_by_key[key] = reg
        self._entities_by_pathtail[path] = reg

        return reg

    def get_endpoints(self):
        return self._endpoint_registrations_by_key.values()


def link_format_from_message(message):
    try:
        if message.opt.content_format == aiocoap.numbers.media_types_rev['application/link-format']:
            return link_header.parse(message.payload.decode('utf8'))
        # FIXME this should support json/cbor too
        else:
            raise error.UnsupportedMediaType()
    except (UnicodeDecodeError, link_header.ParseException):
        raise error.BadRequest()


class ThingWithCommonRD:
    def __init__(self, common_rd):
        super().__init__()
        self.common_rd = common_rd

class RegistrationInterface(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd"

    @asyncio.coroutine
    def render_post(self, request):
        links = link_format_from_message(request)

        query = query_split(request)
        if 'ep' not in query:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Mandatory ep parameter missing")

        # FIXME deduplicate with _update_params
        if 'lt' in query:
            try:
                lt = int(query['lt'])
            except ValueError:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"lt parameter not integer")
        else:
            lt = None
        # FIXME con needs a good default
        regresource = self.common_rd.initialize_endpoint(ep=query['ep'], lt=lt, con=query.get('con', request.remote.uri), d=query.get('d', None), et=query.get('et', None))
        regresource.links = links

        return aiocoap.Message(code=aiocoap.CREATED, location_path=regresource.path)

class RegistrationResource(Resource):
    """The resource object wrapping a registration is just a very thin and
    ephemeral object; all those methods could just as well be added to
    Registration with `s/self.reg/self/g`, making RegistrationResource(reg) =
    reg, but this is kept here for better separation of model and interface."""

    def __init__(self, registration):
        self.reg = registration

    @asyncio.coroutine
    def render_get(self, request):
        return aiocoap.Message(payload=str(self.reg.links).encode('utf8'), content_format=aiocoap.numbers.media_types_rev['application/link-format'])

    def _update_params(self, msg): # may raise ValueError
        # FIXME: deduplicate with RegistrationInterface.render_post
        query = query_split(msg)
        args = {}
        if 'lt' in query:
            self.reg.lt = int(query['lt'])
        if 'con' in query:
            self.reg.con = query['con']
        self.reg.refresh_timeout()

    @asyncio.coroutine
    def render_post(self, request):
        self.reg._update_params(request)
        if not (request.opt.content_format is None and request.payload == b''):
            links = link_format_from_message(request)
            raise error.NotImplemented("I suppose this should update and append the links, how is that done exactly?")
#             # FIXME did i get rel= right here? why should it be done like that?
#             original = self.reg._endpoint_registrations_by_key[key]
#             original_indexed = {(l.href, getattr(l, 'rel', None)): l for l in original.links.links}
#             for l in data.links:
#                 indexkey = (l.href, getattr(l, 'rel', None))
#                 if indexkey in original_indexed:
#                     original.links.links.remove(original_indexed[indexkey])
#                 original.links.links.append(l)
        return aiocoap.Message(code=aiocoap.CHANGED)

    @asyncio.coroutine
    def render_put(self, request):
        # this is not mentioned in the current spec, but seems to make sense
        links = link_format_from_message(request)

        self.reg._update_params(request)
        self.reg.links = links

        return aiocoap.Message(code=aiocoap.CHANGED)

    def render_delete(self, request):
        self.reg.delete()

        return aiocoap.Message(code=aiocoap.DELETED)

class EntityDispatchSite(ThingWithCommonRD, Resource, PathCapable):
    @asyncio.coroutine
    def render(self, request):
        try:
            entity = self.common_rd._entities_by_pathtail[request.opt.uri_path]
        except KeyError:
            raise error.NotFound

        if isinstance(entity, CommonRD.Registration):
            entity = RegistrationResource(entity)
        else:
            raise ValueError("Unexpected object in entities")

        return entity.render(request.copy(uri_path=()))

class GroupRegistrationInterface(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd-group"

class EndpointLookupInterface(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd-lookup-ep"

    @asyncio.coroutine
    def render_get(self, request):
        query = query_split(request)

        candidates = self.common_rd.get_endpoints()
        # FIXME which of the below can be done on the generated host links with
        # generic filtering rules, which would for example do =...* right?
        if 'href' in query:
            candidates = (c for c in candidates if c.href == query['href'])
        if 'd' in query:
            candidates = (c for c in candidates if c.d == query['d'])
        if 'ep' in query:
            candidates = (c for c in candidates if c.ep == query['ep'])
        if 'gp' in query:
            pass # FIXME
        if 'rt' in query:
            pass # FIXME
        if 'et' in query:
            candidates = (c for c in candidates if c.et == query['et'])

        try:
            candidates = list(candidates)
            if 'page' in query:
                candidates = candidates[int(query['page']) * int(query['count']):]
            if 'count' in query:
                candidates = candidates[:int(query['count'])]
        except (KeyError, ValueError):
            raise BadRequest("page requires count, and both must be ints")

        result = [c.get_host_link() for c in candidates]

        return aiocoap.Message(payload=str(LinkHeader(result)).encode('utf8'), content_format=40)

class ResourceLookupInterface(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd-lookup-res"

    @asyncio.coroutine
    def render_get(self, request):
        query = query_split(request)

        eps = self.common_rd.get_endpoints()
        if 'd' in query:
            eps = (e for e in eps if e.d == query['d'])
        if 'ep' in query:
            eps = (e for e in eps if e.ep == query['ep'])
        if 'gp' in query:
            pass # FIXME
        if 'et' in query:
            eps = (e for e in eps if e.et == query['et'])

        candidates = itertools.chain(*(e.get_conned_links().links for e in eps))
        for other_query in query:
            if other_query in ('d', 'ep', 'gp', 'et', 'page', 'count'):
                continue
            candidates = (l for l in candidates if getattr(l, other_query) == query[other_query])

        try:
            candidates = list(candidates)
            if 'page' in query:
                candidates = candidates[int(query['page']) * int(query['count'])]
            if 'count' in query:
                candidates = candidates[:int(query['count'])]
        except (KeyError, ValueError):
            raise BadRequest("page requires count, and both must be ints")

        return aiocoap.Message(payload=str(LinkHeader(candidates)).encode('utf8'), content_format=40)

class GroupLookupInterface(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd-lookup-gp"

class SimpleRegistrationWKC(WKCResource):
    def __init__(self, listgenerator, common_rd):
        super().__init__(listgenerator)
        self.common_rd = common_rd

    @asyncio.coroutine
    def render_post(self, request):
        # FIXME deduplicate with _update_params / RegistrationInterface.render_post

        query = query_split(request)
        if 'ep' not in query:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Mandatory ep parameter missing")

        if 'lt' in query:
            try:
                lt = int(query['lt'])
            except ValueError:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"lt parameter not integer")
        else:
            lt = None

        asyncio.Task(self.process_request(
                ep=query['ep'],
                lt=lt,
                con=query.get('con', request.remote.uri),
                d=query.get('d', None),
                et=query.get('et', None),
            ))

        return aiocoap.Message(code=aiocoap.CHANGED)

    @asyncio.coroutine
    def process_request(self, ep, lt, con, d, et):
        # FIXME actually we should have complained about the con uri not being in host-only form ... and is that defined at all?
        fetch_address = (con + '/.well-known/core')

        print(fetch_address)

        try:
            response = yield from self.context.request(aiocoap.Message(code=aiocoap.GET, uri=fetch_address)).response_raising
            links = link_format_from_message(response)
        except Exception as e:
            logging.error("The request triggered for simple registration of %s failed.", con)
            logging.exception(e)
            return

        registration = self.common_rd.initialize_endpoint(ep=ep, lt=lt, con=con, d=d)
        registration.links = links

class StandaloneResourceDirectory(Site):
    """A site that contains all function sets of the CoAP Resource Directoru

    To prevent or show ossification of example paths in the specification, all
    function set paths are configurable and default to values that are
    different from the specification (but still recognizable)."""

    rd_path = ("resourcedirectory",)
    group_path = ("resourcedirectory-group",)
    ep_lookup_path = ("endpoint-lookup",)
    gp_lookup_path = ("group-lookup",)
    res_lookup_path = ("resource-lookup",)

    def __init__(self):
        super().__init__()

        common_rd = CommonRD()

        self._simple_wkc = SimpleRegistrationWKC(self.get_resources_as_linkheader, common_rd=common_rd)
        self.add_resource((".well-known", "core"), self._simple_wkc)

        self.add_resource(self.rd_path, RegistrationInterface(common_rd=common_rd))
        self.add_resource(self.group_path, GroupRegistrationInterface(common_rd=common_rd))
        self.add_resource(self.ep_lookup_path, EndpointLookupInterface(common_rd=common_rd))
        self.add_resource(self.gp_lookup_path, GroupLookupInterface(common_rd=common_rd))
        self.add_resource(self.res_lookup_path, ResourceLookupInterface(common_rd=common_rd))

        self.add_resource(common_rd.entity_prefix, EntityDispatchSite(common_rd=common_rd))

        self.common_rd = common_rd

    @asyncio.coroutine
    def shutdown(self):
        yield from self.common_rd.shutdown()

    # the need to pass this around crudely demonstrates that the setup of sites
    # and contexts direly needs improvement, and thread locals are giggling
    # about my stubbornness
    def set_context(self, new_context):
        self._simple_wkc.context = new_context

def build_parser():
    p = argparse.ArgumentParser(description=__doc__)

    p.add_argument('--server-address', help="Address to bind the server context to", metavar="HOST", default="::")
    p.add_argument('--server-port', help="Port to bind the server context to", metavar="PORT", default=aiocoap.COAP_PORT, type=int)

    return p

class Main(AsyncCLIDaemon):
    @asyncio.coroutine
    def start(self, args=None):
        parser = build_parser()
        options = parser.parse_args(args if args is not None else sys.argv[1:])

        self.site = StandaloneResourceDirectory()

        self.context = yield from aiocoap.Context.create_server_context(self.site, bind=(options.server_address, options.server_port))
        self.site.set_context(self.context)

    @asyncio.coroutine
    def shutdown(self):
        yield from self.site.shutdown()
        yield from self.context.shutdown()

sync_main = Main.sync_main

if __name__ == "__main__":
    sync_main()
