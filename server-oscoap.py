#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

import aiocoap.resource as resource
import aiocoap.error as error
import aiocoap
import aiocoap.oscoap as oscoap
from aiocoap.util import hostportjoin

from server import BlockResource, SeparateLargeResource, TimeResource

class PleaseUseOscoap(error.ConstructionRenderableError):
    code = aiocoap.UNAUTHORIZED
    message = "Please use OSCOAP"

class PrivateSite(resource.Site):
    def __init__(self, *, contexts=[]):
        super().__init__()
        self.contexts = {c.cid: c for c in contexts}

    @asyncio.coroutine
    def render(self, request):
        try:
            cid, sid = oscoap.verify_start(request)
        except oscoap.NotAProtectedMessage:
            raise PleaseUseOscoap()

        # right now we'll rely on the sid to match, especially as it's not sent
        # unconditionally anyway
        try:
            sc = self.contexts[cid]
        except KeyError:
            raise PleaseUseOscoap() # may we disclose the reason?

        unprotected, seqno = sc.unprotect(request)

        # FIXME the render doesn't provide a way to provide context in the
        # sense of "who is the user"; obviously, the render interface needs
        # rework
        response = (yield from super().render(unprotected))

        if response.code is None:
            # FIXME: this duplicates the default setting in aiocoap.protocol
            response.code = aiocoap.CONTENT

        protected_response, _ = sc.protect(response, request_seq=seqno)

        # FIXME who should trigger this?
        sc._store()

        return protected_response

def main():
    # Resource tree creation
    root = PrivateSite(contexts=[oscoap.FilesystemSecurityContext('./demo-context-recipient', 'recipient')])

    root.add_resource(('.well-known', 'core'), resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(('time',), TimeResource())
    root.add_resource(('other', 'block'), BlockResource())
    root.add_resource(('other', 'separate'), SeparateLargeResource())

    asyncio.Task(aiocoap.Context.create_server_context(root))

    asyncio.get_event_loop().run_forever()

if __name__ == "__main__":
    main()
