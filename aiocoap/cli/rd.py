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

        def __init__(self, con, timeout_cb, d=None, lt=None, et=None):
            self.links = LinkHeader([])
            self.d = d
            self.lt = lt or 86400
            self.et = et
            self.con = con

            self.timeout_cb = timeout_cb
            self._set_timeout()

        def _set_timeout(self):
            self.timeout = asyncio.get_event_loop().call_later(self.lt + self.grace_period, self.timeout_cb)

        def refresh_timeout(self):
            self.timeout.cancel()
            self._set_timeout()

    @asyncio.coroutine
    def shutdown(self):
        pass

    def initialize_endpoint(self, key, con, lt=None, et=None, d=None):
        try:
            self._endpoints[key].timeout.cancel()
            del self._endpoints[key]
        except KeyError:
            pass

        self._endpoints[key] = self.RegisteredEndpoint(con=con,
                timeout_cb=functools.partial(self.delete_key, key),
                lt=lt, et=et, d=d)

        # this was the brutal way towards idempotency (delete and re-create).
        # if any actions based on that are implemented here, they have yet to
        # decide wheter they'll treat idempotent recreations like deletions or
        # just ignore them unless something otherwise unchangeable (et, d)
        # changes.

    def update_endpoint(self, lt=None, con=None):
        # FIXME this has no callers
        endpoint = self._endpoints[key]
        if lt:
            endpoint.lt = lt
        if con:
            endpoint.con = con
        endpoint.refresh_timeout()

    def set_published_links(self, key, data):
        self._endpoints[key].links = data

    def update_published_links(self, key, data):
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
            return (*self.registration_path_prefix, key[0])
        else:
            return (*self.registration_path_prefix, key[1], key[0])

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

        query = dict(q.split('=', 1) for q in request.opt.uri_query if '=' in q)
        try:
            key = self.common_rd.get_key_from_ep_d(query['ep'], query.get('d', None))
        except KeyError:
            return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Mandatory ep parameter missing")

        # FIXME continue here
        if 'lt' in query:
            try:
                lt = int(query['lt'])
            except ValueError:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"lt parameter not integer")
        else:
            lt = None
        self.common_rd.initialize_endpoint(key, lt=lt, con=query.get('con', None))
        self.common_rd.set_published_links(key, links)

        return aiocoap.Message(code=aiocoap.CREATED, location_path=self.common_rd.get_path_for_key(key))

class RDFunctionSetLocations(ThingWithCommonRD, Resource, PathCapable):
    def render_get(self, request):
        full_path = self.common_rd.registration_path_prefix + request.opt.uri_path
        try:
            key = self.common_rd.get_key_for_path(full_path)
            data = self.common_rd.get_published_links(key)
        except KeyError:
            return aiocoap.Message(code=aiocoap.NOT_FOUND)

        return aiocoap.Message(payload=str(data).encode('utf8'), content_format=aiocoap.numbers.media_types_rev['application/link-format'])

    def render_post(self, request):
        links = link_format_from_message(request)

        full_path = self.common_rd.registration_path_prefix + request.opt.uri_path
        try:
            key = self.common_rd.get_key_for_path(full_path)
            self.common_rd.update_published_links(key, links)
        except KeyError:
            return aiocoap.Message(code=aiocoap.NOT_FOUND)

        # FIXME: update lt, con, last-seen
        return aiocoap.Message(code=aiocoap.CHANGED)

    def render_delete(self, request):
        full_path = self.common_rd.registration_path_prefix + request.opt.uri_path
        try:
            key = self.common_rd.get_key_for_path(full_path)
            self.common_rd.delete_key(key)
        except KeyError:
            return aiocoap.Message(code=aiocoap.NOT_FOUND)

        return aiocoap.Message(code=aiocoap.DELETED)

class RDGroupFunctionSet(ThingWithCommonRD, Resource):
    ct = 40
    rt = "core.rd-group"

class RDGroupFunctionSetLocations(ThingWithCommonRD, Resource, PathCapable):
    pass

class RDLookupFunctionSet(Site):
    ct = 40
    rt = "core.rd-lookup"

    def __init__(self, common_rd):
        super().__init__()
        self.add_resource(('ep',), self.EP(common_rd=common_rd))
        self.add_resource(('d',), self.D(common_rd=common_rd))
        self.add_resource(('res',), self.Res(common_rd=common_rd))
        self.add_resource(('gp',), self.Gp(common_rd=common_rd))

    class EP(ThingWithCommonRD, Resource):
        @asyncio.coroutine
        def render_get(self, request):
            return aiocoap.Message(payload=b"EP got!")

    class D(ThingWithCommonRD, Resource):
        pass

    class Res(ThingWithCommonRD, Resource):
        pass

    class Gp(ThingWithCommonRD, Resource):
        pass

class SimpleRegistrationWKC(WKCResource):
    def __init__(self, listgenerator, common_rd):
        super().__init__(listgenerator)
        self.common_rd = common_rd

    @asyncio.coroutine
    def render_post(self, request):
        # FIXME that's not an implementation
        return aiocoap.Message(code=aiocoap.CHANGED)

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

        self.add_resource((".well-known", "core"), SimpleRegistrationWKC(self.get_resources_as_linkheader, common_rd=common_rd))

        self.add_resource(self.rd_path, RDFunctionSet(common_rd=common_rd))
        self.add_resource(self.group_path, RDGroupFunctionSet(common_rd=common_rd))
        self.add_resource(self.lookup_path, RDLookupFunctionSet(common_rd=common_rd))

        self.add_resource(common_rd.registration_path_prefix, RDFunctionSetLocations(common_rd=common_rd))
        self.add_resource(common_rd.group_path_prefix, RDGroupFunctionSetLocations(common_rd=common_rd))

def parse_commandline(args):
    p = argparse.ArgumentParser(description=__doc__)

    p.add_argument('--server-address', help="Address to bind the server context to", metavar="HOST", default="::")
    p.add_argument('--server-port', help="Port to bind the server context to", metavar="PORT", default=aiocoap.COAP_PORT, type=int)

    return p, p.parse_args(args)

class Main(AsyncCLIDaemon):
    @asyncio.coroutine
    def start(self, args=None):
        parser, options = parse_commandline(args if args is not None else sys.argv[1:])

        self.common_rd = CommonRD()

        site = StandaloneResourceDirectory(common_rd=self.common_rd)

        self.context = yield from aiocoap.Context.create_server_context(site, bind=(options.server_address, options.server_port))

    @asyncio.coroutine
    def shutdown(self):
        yield from self.context.shutdown()
        yield from self.common_rd.shutdown()

sync_main = Main.sync_main

if __name__ == "__main__":
    sync_main()
