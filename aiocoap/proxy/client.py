# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import warnings

from ..message import UndecidedRemote
from .. import interfaces
from ..protocol import ClientObservation

from ..util import hostportsplit
from ..util.asyncio import py38args

class ProxyForwarder(interfaces.RequestProvider):
    """Object that behaves like a Context but only provides the request
    function and forwards all messages to a proxy.

    This is not a proxy itself, it is just the interface for an external
    one."""
    def __init__(self, proxy_address, context):
        if '://' not in proxy_address:
            warnings.warn("Proxy addresses without scheme are deprecated, "
                    "please specify like `coap://host`, `coap+tcp://ip:port` "
                    "etc.", DeprecationWarning)
            proxy_address = 'coap://' + proxy_address

        self.proxy_address = UndecidedRemote.from_pathless_uri(proxy_address)
        self.context = context

    proxy = property(lambda self: self._proxy)

    def request(self, message, **kwargs):
        if not isinstance(message.remote, UndecidedRemote):
            raise ValueError(
                "Message already has a configured "\
                "remote, set .opt.uri_{host,port} instead of remote")
        host, port = hostportsplit(message.remote.hostinfo)
        message.opt.uri_port = port
        message.opt.uri_host = host
        message.opt.proxy_scheme = self.proxy_address.scheme
        message.remote = self.proxy_address

        return self.context.request(message)
