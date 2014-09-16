# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import socket

import asyncio

from . import interfaces

class ProxyForwarder(interfaces.RequestProvider):
    """Object that behaves like a Context but only provides the request
    function and forwards all messages to a proxy.

    This is not a proxy itself, it is just the interface for an external
    one."""
    def __init__(self, proxy_address, context):
        self.proxy_address = proxy_address
        self.context = context

    proxy = property(lambda self: self._proxy)

    def request(self, message):
        assert message.remote is None, "Message already has a configured "\
                "remote, set .opt.uri_{host,port} instead of remote"
        assert message.opt.uri_host is not None, "Message does not have a "\
                "destination address"
        message.opt.proxy_scheme = 'coap'
        return ProxyRequest(self, message)

class ProxyRequest(interfaces.Request):
    def __init__(self, proxy, app_request):
        self.proxy = proxy
        self.app_request = app_request
        self.response = asyncio.Future()

        asyncio.async(self._launch())

    @asyncio.coroutine
    def _launch(self):
        try:
            self.app_request.remote = None
            self.app_request.unresolved_remote = self.proxy.proxy_address
            proxyrequest = self.proxy.context.request(self.app_request)
            self.response.set_result((yield from proxyrequest.response))
        except Exception as e:
            self.response.set_exception(e)
