#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import datetime
import logging

import asyncio

import aiocoap.resource as resource
import aiocoap


class BlockResource(resource.Resource):
    """
    Example resource which supports GET and PUT methods. It sends large
    responses, which trigger blockwise transfer.
    """

    def __init__(self):
        super(BlockResource, self).__init__()
        self.content = ("This is the resource's default content. It is padded "\
                "with numbers to be large enough to trigger blockwise "\
                "transfer.\n" + "0123456789\n" * 100).encode("ascii")

    @asyncio.coroutine
    def render_get(self, request):
        response = aiocoap.Message(code=aiocoap.CONTENT, payload=self.content)
        return response

    @asyncio.coroutine
    def render_put(self, request):
        print('PUT payload: %s' % request.payload)
        self.content = request.payload
        payload = ("I've accepted the new payload. You may inspect it here in "\
                "Python's repr format:\n\n%r"%self.content).encode('utf8')
        return aiocoap.Message(code=aiocoap.CHANGED, payload=payload)


class SeparateLargeResource(resource.Resource):
    """
    Example resource which supports GET method. It uses asyncio.sleep to
    simulate a long-running operation, and thus forces the protocol to send
    empty ACK first.
    """

    def __init__(self):
        super(SeparateLargeResource, self).__init__()
#        self.add_param(resource.LinkParam("title", "Large resource."))

    @asyncio.coroutine
    def render_get(self, request):
        yield from asyncio.sleep(3)

        payload = "Three rings for the elven kings under the sky, seven rings"\
                "for dwarven lords in their halls of stone, nine rings for"\
                "mortal men doomed to die, one ring for the dark lord on his"\
                "dark throne.".encode('ascii')
        return aiocoap.Message(code=aiocoap.CONTENT, payload=payload)

class TimeResource(resource.ObservableResource):
    """
    Example resource that can be observed. The `notify` method keeps scheduling
    itself, and calles `update_state` to trigger sending notifications.
    """
    def __init__(self):
        super(TimeResource, self).__init__()

        self.notify()

    def notify(self):
        self.updated_state()
        asyncio.get_event_loop().call_later(6, self.notify)

    def update_observation_count(self, count):
        if count:
            # not that it's actually implemented like that here -- unconditional updating works just as well
            print("Keeping the clock nearby to trigger observations")
        else:
            print("Stowing away the clock until someone asks again")

    @asyncio.coroutine
    def render_get(self, request):
        payload = datetime.datetime.now().strftime("%Y-%m-%d %H:%M").encode('ascii')
        return aiocoap.Message(code=aiocoap.CONTENT, payload=payload)

#class CoreResource(resource.Resource):
#    """
#    Example Resource that provides list of links hosted by a server.
#    Normally it should be hosted at /.well-known/core
#
#    Notice that self.visible is not set - that means that resource won't
#    be listed in the link format it hosts.
#    """
#
#    def __init__(self, root):
#        resource.Resource.__init__(self)
#        self.root = root
#
#    @asyncio.coroutine
#    def render_get(self, request):
#        data = []
#        self.root.generate_resource_list(data, "")
#        payload = ",".join(data).encode('utf-8')
#        response = aiocoap.Message(code=aiocoap.CONTENT, payload=payload)
#        response.opt.content_format = 40
#        return response

# logging setup

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

def main():
    # Resource tree creation
    root = resource.Site()

    root.add_resource(('.well-known', 'core'), resource.WKCResource(root.get_resources_as_linkheader))

    root.add_resource(('time',), TimeResource())

    root.add_resource(('other', 'block'), BlockResource())

    root.add_resource(('other', 'separate'), SeparateLargeResource())

    asyncio.async(aiocoap.Context.create_server_context(root))

    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()
