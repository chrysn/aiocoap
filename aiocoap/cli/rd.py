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
import abc
import functools

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

    registration_path_prefix = ("ep",)
    group_path_prefix = ("gp",)

    def __init__(self):
        super().__init__()

        self._endpoints = {} # key -> RegisteredEndpoint

    class RegisteredEndpoint:
        grace_period = 15

        def __init__(self, con, timeout_cb, ep, d=None, lt=None, et=None):
            self.links = LinkHeader([])
            self.ep = ep
            self.d = d
            self.lt = lt or 86400
            self.et = et
            self.con = con

            self.timeout_cb = timeout_cb
            self._set_timeout()

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
            self.timeout = asyncio.Task(longwait(delay, self.timeout_cb))

        def refresh_timeout(self):
            self.timeout.cancel()
            self._set_timeout()

        def get_host_link(self):
            args = {'ep': self.ep}
            if self.d:
                args['d'] = self.d
            if self.et:
                args['et'] = self.et
            return Link(href=self.con, **args)

        def get_all_links(self):
            result = []
            for l in self.links.links:
                href = self.con + l.href if l.href.startswith('/') else l.href
                data = [[k, self.con + v if (k == 'anchor' and v.startswith('/')) else v] for (k, v) in l.attr_pairs]
                result.append(Link(href, data))
            return LinkHeader(result)

    @asyncio.coroutine
    def shutdown(self):
        pass

    def initialize_endpoint(self, key, con, ep, lt=None, et=None, d=None):
        try:
            self._endpoints[key].timeout.cancel()
            del self._endpoints[key]
        except KeyError:
            pass

        self._endpoints[key] = self.RegisteredEndpoint(con=con,
                timeout_cb=functools.partial(self.delete_key, key),
                ep=ep, lt=lt, et=et, d=d)

        # this was the brutal way towards idempotency (delete and re-create).
        # if any actions based on that are implemented here, they have yet to
        # decide wheter they'll treat idempotent recreations like deletions or
        # just ignore them unless something otherwise unchangeable (ep, d)
        # changes.

    def update_endpoint(self, key, lt=None, con=None):
        endpoint = self._endpoints[key]
        if lt:
            endpoint.lt = lt
        if con:
            endpoint.con = con
        endpoint.refresh_timeout()

    def set_published_links(self, key, data):
        self._endpoints[key].links = data

    def update_published_links(self, key, data):
        # FIXME did i get rel= right here? why should it be done like that? 
        original = self._endpoints[key]
        original_indexed = {(l.href, getattr(l, 'rel', None)): l for l in original.links.links}
        for l in data.links:
            indexkey = (l.href, getattr(l, 'rel', None))
            if indexkey in original_indexed:
                original.links.links.remove(original_indexed[indexkey])
            original.links.links.append(l)

    def get_published_links(self, key):
        return self._endpoints[key].links

    def delete_key(self, key):
        self._endpoints[key].timeout.cancel()
        del self._endpoints[key]

    def get_path_for_key(self, key):
        if key[1] is None:
            return self.registration_path_prefix + (key[0], )
        else:
            return self.registration_path_prefix + (key[1], key[0])

    def get_key_for_path(self, path):
        if path[:len(self.registration_path_prefix)] != self.registration_path_prefix:
            raise KeyError()
        path = path[len(self.registration_path_prefix):]
        if len(path) == 1:
            key = (path[0], None)
        elif len(path) == 2:
            key = (path[1], path[0])
        else:
            raise KeyError()

        if key not in self._endpoints:
            raise KeyError()
        return key

    def get_key_from_ep_d(self, ep, d):
        """Construct a key from a given endpoint and domain name

        This not so much abstracts away the internals of how a key is built as
        it provides a point where things will break if the key construction
        needs to change."""
        return (ep, d)

    def get_endpoints(self):
        # FIXME if we start handing out RegisteredEndpoint objects here, we can
        # just as well embrace that and deal in RegisteredEndpoint objects (eg
        # instead of keys) in other places too
        return self._endpoints.values()


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

class RDFunctionSet(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd"

    @asyncio.coroutine
    def render_post(self, request):
        links = link_format_from_message(request)

        query = query_split(request)
        try:
            key = self.common_rd.get_key_from_ep_d(query['ep'], query.get('d', None))
        except KeyError:
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
        self.common_rd.initialize_endpoint(key, ep=query['ep'], lt=lt, con=query.get('con', request.remote.uri), d=query.get('d', None), et=query.get('et', None))
        self.common_rd.set_published_links(key, links)

        return aiocoap.Message(code=aiocoap.CREATED, location_path=self.common_rd.get_path_for_key(key))

class RDFunctionSetLocations(ThingWithCommonRD, Resource, PathCapable):
    # FIXME the render_ functions look too similar on this one!
    def render_get(self, request):
        full_path = self.common_rd.registration_path_prefix + request.opt.uri_path
        try:
            key = self.common_rd.get_key_for_path(full_path)
            data = self.common_rd.get_published_links(key)
        except KeyError:
            return aiocoap.Message(code=aiocoap.NOT_FOUND)

        return aiocoap.Message(payload=str(data).encode('utf8'), content_format=aiocoap.numbers.media_types_rev['application/link-format'])

    def render_post(self, request):
        full_path = self.common_rd.registration_path_prefix + request.opt.uri_path
        try:
            key = self.common_rd.get_key_for_path(full_path)
            # should probably be processed in an atomic fashion... nvm
            self._update_params(key, request)
            if not (request.opt.content_format is None and request.payload == b''):
                links = link_format_from_message(request)
                self.common_rd.update_published_links(key, links)
        except KeyError:
            return aiocoap.Message(code=aiocoap.NOT_FOUND)

        return aiocoap.Message(code=aiocoap.CHANGED)

    def render_put(self, request):
        # this is not mentioned in the spec, but seems to make sense
        links = link_format_from_message(request)

        full_path = self.common_rd.registration_path_prefix + request.opt.uri_path
        try:
            key = self.common_rd.get_key_for_path(full_path)
            self._update_params(key, request)
            self.common_rd.set_published_links(key, links)
        except KeyError:
            return aiocoap.Message(code=aiocoap.NOT_FOUND)

        return aiocoap.Message(code=aiocoap.CHANGED)

    def render_delete(self, request):
        full_path = self.common_rd.registration_path_prefix + request.opt.uri_path
        try:
            key = self.common_rd.get_key_for_path(full_path)
            self.common_rd.delete_key(key)
        except KeyError:
            return aiocoap.Message(code=aiocoap.NOT_FOUND)

        return aiocoap.Message(code=aiocoap.DELETED)

    # FIXME patch not implemented

    def _update_params(self, key, msg): # may raise ValueError
        # FIXME: deduplicate with RDFunctionSet.render_post
        query = query_split(msg)
        args = {}
        if 'lt' in query:
            args['lt'] = int(query['lt'])
        if 'con' in query:
            args['con'] = query['con']
        self.common_rd.update_endpoint(key, **args)

class RDGroupFunctionSet(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd-group"

class RDGroupFunctionSetLocations(ThingWithCommonRD, Resource, PathCapable):
    pass

class RDLookupFunctionSet(Site):
    def __init__(self, common_rd):
        super().__init__()
        self.add_resource(('ep',), self.EP(common_rd=common_rd))
        self.add_resource(('d',), self.D(common_rd=common_rd))
        self.add_resource(('res',), self.Res(common_rd=common_rd))
        self.add_resource(('gp',), self.Gp(common_rd=common_rd))

    class EP(ThingWithCommonRD, Resource):
        ct = 40
        rt = "core.rd-lookup-ep"

        @asyncio.coroutine
        def render_get(self, request):
            query = query_split(request)

            candidates = self.common_rd.get_endpoints()
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
                    candidates = candidates[int(query['page']) * int(query['count'])]
                if 'count' in query:
                    candidates = candidates[:int(query['count'])]
            except (KeyError, ValueError):
                raise BadRequest("page requires count, and both must be ints")

            result = [c.get_host_link() for c in candidates]

            return aiocoap.Message(payload=str(LinkHeader(result)).encode('utf8'), content_format=40)

    class D(ThingWithCommonRD, Resource):
        ct = 40
        rt = "core.rd-lookup-d"

        @asyncio.coroutine
        def render_get(self, request):
            query = query_split(request)

            candidates = self.common_rd.get_endpoints()
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

            candidates = sorted(set(c.d for c in candidates if c.d is not None))

            try:
                if 'page' in query:
                    candidates = candidates[int(query['page']) * int(query['count'])]
                if 'count' in query:
                    candidates = candidates[:int(query['count'])]
            except (KeyError, ValueError):
                raise BadRequest("page requires count, and both must be ints")

            return aiocoap.Message(payload=",".join('<>;d="%s"'%c for c in candidates).encode('utf8'), content_format=40)

    class Res(ThingWithCommonRD, Resource):
        ct = 40
        rt = "core.rd-lookup-res"

        @asyncio.coroutine
        def render_get(self, request):
            query = query_split(request)

            eps = self.common_rd.get_endpoints()
            candidates = sum(([(e, l) for l in e.get_all_links().links] for e in eps), [])
            if 'd' in query:
                candidates = ([e, l] for [e, l] in candidates if e.d == query['d'])
            if 'ep' in query:
                candidates = ([e, l] for [e, l] in candidates if e.ep == query['ep'])
            if 'gp' in query:
                pass # FIXME
            if 'rt' in query:
                candidates = ([e, l] for [e, l] in candidates if query['rt'] in l.rt)
            if 'et' in query:
                candidates = ([e, l] for [e, l] in candidates if e.et == query['et'])
            for other_query in query:
                if other_query in ('d', 'ep', 'gp', 'rt', 'et', 'page', 'count'):
                    continue
                candidates = ([e, l] for [e, l] in candidates if getattr(e, other_query) == query[other_query])

            try:
                candidates = list(candidates)
                if 'page' in query:
                    candidates = candidates[int(query['page']) * int(query['count'])]
                if 'count' in query:
                    candidates = candidates[:int(query['count'])]
            except (KeyError, ValueError):
                raise BadRequest("page requires count, and both must be ints")

            result = [l for (e, l) in candidates]

            return aiocoap.Message(payload=str(LinkHeader(result)).encode('utf8'), content_format=40)

    class Gp(ThingWithCommonRD, Resource):
        ct = 40
        rt = "core.rd-lookup-gp"

        pass

class SimpleRegistrationWKC(WKCResource):
    def __init__(self, listgenerator, common_rd):
        super().__init__(listgenerator)
        self.common_rd = common_rd

    @asyncio.coroutine
    def render_post(self, request):
        # FIXME deduplicate with _update_params / RDFunctionSet.render_post

        query = query_split(request)
        try:
            key = self.common_rd.get_key_from_ep_d(query['ep'], query.get('d', None))
        except KeyError:
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

        key = self.common_rd.get_key_from_ep_d(ep, d)
        self.common_rd.initialize_endpoint(key, ep=ep, lt=lt, con=con, d=d)
        self.common_rd.set_published_links(key, links)

class StandaloneResourceDirectory(Site):
    """A site that contains all function sets of the CoAP Resource Directoru

    To prevent or show ossification of example paths in the specification, all
    function set paths are configurable and default to values that are
    different from the specification (but still recognizable)."""

    rd_path = ("resourcedirectory",)
    group_path = ("resourcedirectory-group",)
    lookup_path = ("resouredirectory-lookup",)

    def __init__(self, *, common_rd=None):
        super().__init__()

        if common_rd is None:
            common_rd = CommonRD()

        self._simple_wkc = SimpleRegistrationWKC(self.get_resources_as_linkheader, common_rd=common_rd)
        self.add_resource((".well-known", "core"), self._simple_wkc)

        self.add_resource(self.rd_path, RDFunctionSet(common_rd=common_rd))
        self.add_resource(self.group_path, RDGroupFunctionSet(common_rd=common_rd))
        self.add_resource(self.lookup_path, RDLookupFunctionSet(common_rd=common_rd))

        self.add_resource(common_rd.registration_path_prefix, RDFunctionSetLocations(common_rd=common_rd))
        self.add_resource(common_rd.group_path_prefix, RDGroupFunctionSetLocations(common_rd=common_rd))

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

        self.common_rd = CommonRD()

        site = StandaloneResourceDirectory(common_rd=self.common_rd)

        self.context = yield from aiocoap.Context.create_server_context(site, bind=(options.server_address, options.server_port))
        site.set_context(self.context)

    @asyncio.coroutine
    def shutdown(self):
        yield from self.context.shutdown()
        yield from self.common_rd.shutdown()

sync_main = Main.sync_main

if __name__ == "__main__":
    sync_main()
