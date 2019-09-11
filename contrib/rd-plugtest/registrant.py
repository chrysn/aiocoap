#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""A very limited registrant-ep for Resorce Directory plugtests.

It largely utilizes the client registration features already built into
aiocoap, but also offers a --simple optiion to run the simple registration
that's otherwise not needed in aiocoap as the clients are featureful enough to
be able to do (and need features of) full registration.

Even though aiocoap typically does not emit such links, it produces the
spurious links from the plug test description to see whether the RD deals with
them well.

All three site descriptions from the plug test are selectable with --site; it
is up to the operator to pick the right one for the right test, and to decide
whether to register simply, regularly, or using a CT (which is easily simulated
by making the registrant simply-register at a rd-relay). The --register-as
parameter should have a usable default for the plug test.
"""

import argparse
from urllib.parse import urljoin

from aiocoap import Message, POST
from aiocoap.cli.common import (add_server_arguments,
        server_context_from_arguments)
from aiocoap.util.cli import AsyncCLIDaemon
from aiocoap.resource import Resource, Site, WKCResource
from aiocoap.util.linkformat import LinkFormat, Link
from aiocoap.resourcedirectory.client.register import Registerer

class DemoResource(Resource):
    async def render_get(self, request):
        if request.opt.accept == 41:
            return Message(payload=("<data>%s</data>" % self.text).encode('utf8'), content_format=41)
        else:
            return Message(payload=self.text.encode('utf8'), content_format=0)

class Temp(DemoResource):
    rt = "temperature-c"

    text = "39.1°C"

class Light(DemoResource):
    rt = "light-lux"

    text = "There are four lights."

class Light3(DemoResource):
    rt = "light"
    ct = 0

def build_site_node1():
    site = Site()
    temp = Temp()
    site.add_resource(['sensors', 'temp'], temp)
    light = Light()
    site.add_resource(['sensors', 'light'], light)
    for x in (temp, light):
        x.if_ = "sensor"
        x.ct = 41

    def get_links():
        links = site.get_resources_as_linkheader()
        for l in links.links:
            if l.href == "/sensors/light":
                l.attr_pairs.append(("anchor", "coap://spurious.example.com:5683"))
        return LinkFormat(links.links)
    site.add_resource(['.well-known', 'core'], WKCResource(get_links))

    return site

def build_site_node2():
    site = Site()
    temp = Temp()
    site.add_resource(['temp'], temp)
    light = Light()
    site.add_resource(['light'], light)
    for x in (temp, light):
        x.ct = 0

    def get_links():
        links = site.get_resources_as_linkheader()
        links.links.append(Link("/t", anchor="sensors/temp", rel="alternate"))
        links.links.append(Link("http://www.example.com/sensors/t123", anchor="sensors/temp", rel="describedby"))
        return LinkFormat(links.links)
    site.add_resource(['.well-known', 'core'], WKCResource(get_links))

    return site

def build_site_node3():
    site = Site()
    for x in 'left', 'middle', 'right':
        site.add_resource(['light', x], Light3())
    site.add_resource(['.well-known', 'core'], WKCResource(site.get_resources_as_linkheader))
    return site

class RDRegistrant(AsyncCLIDaemon):
    registerer = None
    async def start(self):
        p = argparse.ArgumentParser()
        p.add_argument("rd_uri", help="Preconfigured address of the resource"
                " directory", nargs='?', default='coap://[ff05::fd]')
        p.add_argument("--simple", help="Run simple registration rather than"
                " full (incomplete: Never renews)", action="store_true")
        p.add_argument("--register-as", help="Endpoint name to register as (default: node$SITE",
                default=None)
        p.add_argument("--site", help="Use a different resource / link layout", default=1, type=int)
        add_server_arguments(p)

        opts = p.parse_args()

        if opts.site == 1:
            site = build_site_node1()
        elif opts.site == 2:
            site = build_site_node2()
        elif opts.site == 3:
            site = build_site_node3()
        else:
            raise p.error("Invalid site value")

        if opts.register_as is None:
            opts.register_as = "node%s" % opts.site

        self.context = await server_context_from_arguments(site, opts)

        if opts.simple:
            rd_wkc = urljoin(opts.rd_uri, '/.well-known/core?ep=%s&lt=6000' % opts.register_as)
            await self.context.request(Message(code=POST, uri=rd_wkc)).response
        else:
            self.registerer = Registerer(self.context, opts.rd_uri, lt=120,
                    registration_parameters={'ep': opts.register_as})

    async def shutdown(self):
        if self.registerer is not None:
            await self.registerer.shutdown()
        await self.context.shutdown()

if __name__ == "__main__":
    RDRegistrant.sync_main()
