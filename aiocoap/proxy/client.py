# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

from .. import interfaces
from ..protocol import ClientObservation

class ProxyForwarder(interfaces.RequestProvider):
    """Object that behaves like a Context but only provides the request
    function and forwards all messages to a proxy.

    This is not a proxy itself, it is just the interface for an external
    one."""
    def __init__(self, proxy_address, context):
        self.proxy_address = proxy_address
        self.context = context

    proxy = property(lambda self: self._proxy)

    def request(self, message, **kwargs):
        assert message.remote is None, "Message already has a configured "\
                "remote, set .opt.uri_{host,port} instead of remote"
        assert message.opt.uri_host is not None, "Message does not have a "\
                "destination address"
        message.opt.proxy_scheme = 'coap'
        return ProxyRequest(self, message, **kwargs)

class ProxyRequest(interfaces.Request):
    def __init__(self, proxy, app_request, exchange_monitor_factory=lambda x:None):
        self.proxy = proxy
        self.app_request = app_request
        self.response = asyncio.Future()
        self._exchange_monitor_factory = exchange_monitor_factory

        self.observation = ProxyClientObservation(app_request)

        asyncio.Task(self._launch())

    @asyncio.coroutine
    def _launch(self):
        try:
            self.app_request.remote = None
            self.app_request.unresolved_remote = self.proxy.proxy_address
            proxyrequest = self.proxy.context.request(self.app_request, exchange_monitor_factory=self._exchange_monitor_factory)
            if proxyrequest.observation is not None:
                self.observation._hook_onto(proxyrequest.observation)
            else:
                self.observation.error(Exception("No proxied observation, this should not have been created in the first place."))
            self.response.set_result((yield from proxyrequest.response))
        except Exception as e:
            self.response.set_exception(e)

class ProxyClientObservation(ClientObservation):
    real_observation = None
    _register = None
    _unregister = None

    def _hook_onto(self, real_observation):
        if self.cancelled:
            real_observation.cancel()
        else:
            real_observation.register_callback(self.callback)
            real_observation.register_errback(self.error)

    def cancel(self):
        self.errbacks = None
        self.callbacks = None
        self.cancelled = True
        if self.real_observation is not None:
            # delay to _hook_onto, will be cancelled there as cancelled is set to True
            self.real_observation.cancel()
