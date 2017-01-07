#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

from aiocoap import *
from aiocoap.oscoap import FilesystemSecurityContext

async def main():
    protocol = await Context.create_client_context()

    security_context = FilesystemSecurityContext('./demo-context/', 'sender')

    request = Message(code=GET, uri='coap://localhost/time')

    protected, seqno = security_context.protect(request)

    response = await protocol.request(protected).response
    print(response)

    unprotected_response, _ = security_context.unprotect(response, seqno)

    print(unprotected_response, unprotected_response.payload)

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())
