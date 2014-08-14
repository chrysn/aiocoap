# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

from . import interfaces

class ProxyForwarder(interfaces.RequestProvider):
    """Object that behaves like a Context but only provides the request
    function and forwards all messages to a proxy.

    This is not a proxy itself, it is just the interface for an external
    one."""
    def __init__(self, host, port, context):
        self._proxy = (host, port)
        self._proxy_remote = None # see _proxy_remote
        self.context = context

    proxy = property(lambda self: self._proxy)

    @asyncio.coroutine
    def _get_proxy_remote(self):
        if self._proxy_remote is None:
            ## @TODO this is very rudimentary; happy-eyeballs or
            # similar could be employed and this be linked into the protocol
            ## @TODO this has since been modified in BaseRequest, before you
            # fix it here, move it to the protocol
            self._proxy_remote = (yield from self.context.loop.getaddrinfo(
                self._proxy[0],
                self._proxy[1] or COAP_PORT
                ))[0][-1]
        return self._proxy_remote

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
            self.app_request.remote = yield from self.proxy._get_proxy_remote()
            proxyrequest = self.proxy.context.request(self.app_request)
            self.response.set_result((yield from proxyrequest.response))
        except Exception as e:
            self.response.set_exception(e)
