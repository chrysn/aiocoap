#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This is a usage example of aiocoap that demonstrates how to implement a
simple client. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import logging
import asyncio
from os import environ

from aiocoap import *
from aiocoap import resource

logging.basicConfig(level=logging.INFO)


async def main():
    # TCPClient that acts as CoAP client and CoAP server
    from server import TimeResource, BlockResource, SeparateLargeResource

    # Offer the same site as the server does
    root = resource.Site()

    root.add_resource(('.well-known', 'core'), resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(('time',), TimeResource())
    root.add_resource(('other', 'block'), BlockResource())
    root.add_resource(('other', 'separate'), SeparateLargeResource())

    tcp_context = await Context.create_client_context(site=root)

    request = Message(code=Code.GET, uri='coap+tcp://localhost/time')

    try:
        response = await tcp_context.request(request).response
    except Exception as e:
        print('Failed to fetch resource:')
        print(e)
    else:
        print('Result: %s\n%r' % (response.code, response.payload))

if __name__ == "__main__":
    asyncio.Task(main())
    asyncio.get_event_loop().run_forever()
