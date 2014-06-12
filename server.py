# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# txThings is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import struct
import random
import copy
import sys
import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap


class CounterResource (resource.CoAPResource):
    """
    Example Resource which supports only GET method. Response is a
    simple counter value.

    Name render_<METHOD> is required by convention. Such method should
    return a Deferred. If the result is available immediately it's best
    to use Twisted method defer.succeed(msg).
    """
   #isLeaf = True

    def __init__(self, start=0):
        resource.CoAPResource.__init__(self)
        self.counter = start
        self.visible = True
        self.add_param(resource.LinkParam("title", "Counter resource"))

    @asyncio.coroutine
    def render_GET(self, request):
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=('%d' % (self.counter,)).encode('ascii'))
        self.counter += 1
        return response


class BlockResource (resource.CoAPResource):
    """
    Example Resource which supports GET, and PUT methods. It sends large
    responses, which trigger blockwise transfer (>64 bytes for normal
    settings).

    As before name render_<METHOD> is required by convention.
    """
    #isLeaf = True

    def __init__(self):
        resource.CoAPResource.__init__(self)
        self.visible = True

    @asyncio.coroutine
    def render_GET(self, request):
        payload=" Now I lay me down to sleep, I pray the Lord my soul to keep, If I shall die before I wake, I pray the Lord my soul to take.".encode('ascii')
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=payload)
        return response

    @asyncio.coroutine
    def render_PUT(self, request):
        print('PUT payload: %s' % request.payload)
        payload = "Mr. and Mrs. Dursley of number four, Privet Drive, were proud to say that they were perfectly normal, thank you very much.".encode('ascii')
        response = aiocoap.Message(code=aiocoap.CHANGED, payload=payload)
        return response


class SeparateLargeResource(resource.CoAPResource):
    """
    Example Resource which supports GET method. It uses callLater
    to force the protocol to send empty ACK first and separate response
    later. Sending empty ACK happens automatically after aiocoap.EMPTY_ACK_DELAY.
    No special instructions are necessary.

    Method render_GET returns a deferred. This allows the protocol to
    do other things, while the answer is prepared.

    Method response_ready uses d.callback(response) to "fire" the deferred,
    and send the response.
    """
    #isLeaf = wTrue

    def __init__(self):
        resource.CoAPResource.__init__(self)
        self.visible = True
        self.add_param(resource.LinkParam("title", "Large resource."))

    @asyncio.coroutine
    def render_GET(self, request):
        yield from asyncio.sleep(3)
        return self.response_ready(request)

    def response_ready(self, request):
        print('response ready. sending...')
        payload = "Three rings for the elven kings under the sky, seven rings for dwarven lords in their halls of stone, nine rings for mortal men doomed to die, one ring for the dark lord on his dark throne.".encode('ascii')
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=payload)
        return response

class TimeResource(resource.CoAPResource):
    def __init__(self):
        resource.CoAPResource.__init__(self)
        self.visible = True
        self.observable = True

        self.notify()

    def notify(self):
        print("i'm trying to send notifications")
        self.updated_state()
        asyncio.get_event_loop().call_later(60, self.notify)

    @asyncio.coroutine
    def render_GET(self, request):
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=datetime.datetime.now().strftime("%Y-%m-%d %H:%M").encode('ascii'))
        return response

class CoreResource(resource.CoAPResource):
    """
    Example Resource that provides list of links hosted by a server.
    Normally it should be hosted at /.well-known/core

    Resource should be initialized with "root" resource, which can be used
    to generate the list of links.

    For the response, an option "Content-Format" is set to value 40,
    meaning "application/link-format". Without it most clients won't
    be able to automatically interpret the link format.

    Notice that self.visible is not set - that means that resource won't
    be listed in the link format it hosts.
    """

    def __init__(self, root):
        resource.CoAPResource.__init__(self)
        self.root = root

    @asyncio.coroutine
    def render_GET(self, request):
        data = []
        self.root.generate_resource_list(data, "")
        payload = ",".join(data).encode('utf-8')
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=payload)
        response.opt.content_format = 40
        return response

# logging setup

logging.getLogger("").setLevel(logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.INFO)
logging.getLogger("coap").setLevel(logging.DEBUG)
logging.debug("server started")

# Resource tree creation
root = resource.CoAPResource()

well_known = resource.CoAPResource()
root.put_child('.well-known', well_known)
core = CoreResource(root)
well_known.put_child('core', core)

counter = CounterResource(5000)
root.put_child('counter', counter)

time = TimeResource()
root.put_child('time', time)

other = resource.CoAPResource()
root.put_child('other', other)

block = BlockResource()
other.put_child('block', block)

separate = SeparateLargeResource()
other.put_child('separate', separate)

loop = asyncio.get_event_loop()

site = resource.Site(root)
transport, protocol = loop.run_until_complete(loop.create_datagram_endpoint(lambda: aiocoap.Endpoint(loop, site), ('127.0.0.1', aiocoap.COAP_PORT)))

loop.run_forever()
