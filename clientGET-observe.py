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

from aiocoap import *

logging.basicConfig(level=logging.INFO)

async def main():
    protocol = await Context.create_client_context()

    request = Message(code=GET, uri='coap://localhost/time', observe=0)

    pr = protocol.request(request)

    # Note that it is necessary to start sending
    r = await pr.response
    print("First response: %s\n%r"%(r, r.payload))

    async for r in pr.observation:
        print("Next result: %s\n%r"%(r, r.payload))

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
