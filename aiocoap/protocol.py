# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains the classes that are responsible for keeping track of
messages:

*   :class:`Context` roughly represents the CoAP endpoint (basically a UDP
    socket) -- something that can send requests and possibly can answer
    incoming requests.

*   a :class:`Request` gets generated whenever a request gets sent to keep
    track of the response

*   a :class:`Responder` keeps track of a single incoming request
"""

import asyncio
import weakref

from . import defaults
from .credentials import CredentialsMap
from .messagemanager import MessageManager, BaseUnicastRequest
from . import interfaces
from .numbers import COAP_PORT

import logging
# log levels used:
# * debug is for things that occur even under perfect conditions.
# * info is for things that are well expected, but might be interesting during
#   testing a network of nodes and not debugging the library. (timeouts,
#   retransmissions, pings)
# * warning is for everything that indicates a malbehaved client. (these don't
#   necessarily indicate a client bug, though; things like requesting a
#   nonexistent block can just as well happen when a resource's content has
#   changed between blocks).

# only for compatibility, to be removed during refactoring
from .messagemanager import ClientObservation, ExchangeMonitor, BlockwiseRequest

class WrappedRemote:
    def __init__(self, manager, inner_address):
        self._manager = weakref.ref(manager)
        self.inner_address = inner_address

    @property
    def manager(self):
        m = self._manager()
        if m is None:
            raise AttributeError("The remote's manager ceased to exist")
        return m

    def __repr__(self):
        return "<%s: %s via %s>" % (self.inner_address, self._manager())

class Context(interfaces.RequestProvider):
    def __init__(self, loop=None, serversite=None, loggername="coap", client_credentials=None):
        self.log = logging.getLogger(loggername)

        self.loop = loop or asyncio.get_event_loop()

        self.serversite = serversite

        self.request_interfaces = []

        self.client_credentials = client_credentials or CredentialsMap()

    #
    # convenience methods for class instanciation
    #

    @classmethod
    async def create_client_context(cls, *, dump_to=None, loggername="coap", loop=None):
        """Create a context bound to all addresses on a random listening port.

        This is the easiest way to get an context suitable for sending client
        requests.
        """

        if loop is None:
            loop = asyncio.get_event_loop()

        self = cls(loop=loop, serversite=None, loggername=loggername)

        # FIXME make defaults overridable (postponed until they become configurable too)
        for transportname in defaults.get_default_clienttransports(loop=loop):
            mman = MessageManager(self)
            if transportname == 'udp6':
                from .transports.udp6 import TransportEndpointUDP6
                mman.message_interface = await TransportEndpointUDP6.create_client_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to)
            elif transportname == 'simple6':
                from .transports.simple6 import TransportEndpointSimple6
                mman.message_interface = await TransportEndpointSimple6.create_client_transport_endpoint(mman, log=self.log, loop=loop)
                # FIXME warn if dump_to is not None
            elif transportname == 'tinydtls':
                from .transports.tinydtls import TransportEndpointTinyDTLS

                mman.message_interface = await TransportEndpointTinyDTLS.create_client_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to)
            else:
                raise RuntimeError("Transport %r not know for client context creation"%transportname)
            self.request_interfaces.append(mman)

        return self

    @classmethod
    async def create_server_context(cls, site, bind=("::", COAP_PORT), *, dump_to=None, loggername="coap-server", loop=None):
        """Create an context, bound to all addresses on the CoAP port (unless
        otherwise specified in the ``bind`` argument).

        This is the easiest way to get a context suitable both for sending
        client and accepting server requests."""

        if loop is None:
            loop = asyncio.get_event_loop()

        self = cls(loop=loop, serversite=site, loggername=loggername)

        for transportname in defaults.get_default_servertransports(loop=loop):
            mman = MessageManager(self)
            if transportname == 'udp6':
                from .transports.udp6 import TransportEndpointUDP6

                mman.message_interface = await TransportEndpointUDP6.create_server_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to, bind=bind)
            # FIXME this is duplicated from the client version, as those are client-only anyway
            elif transportname == 'simple6':
                from .transports.simple6 import TransportEndpointSimple6
                mman.message_interface = await TransportEndpointSimple6.create_client_transport_endpoint(mman, log=self.log, loop=loop)
                # FIXME warn if dump_to is not None
            elif transportname == 'tinydtls':
                from .transports.tinydtls import TransportEndpointTinyDTLS

                mman.message_interface = await TransportEndpointTinyDTLS.create_client_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to)
            # FIXME end duplication
            elif transportname == 'simplesocketserver':
                # FIXME dump_to not implemented
                from .transports.simplesocketserver import TransportEndpointSimpleServer
                mman.message_interface = await TransportEndpointSimpleServer.create_server(bind, mman, log=self.log, loop=loop)
            else:
                raise RuntimeError("Transport %r not know for server context creation"%transportname)
            self.request_interfaces.append(mman)

        return self

    async def shutdown(self):
        await asyncio.wait([ri.shutdown() for ri in self.request_interfaces], timeout=3, loop=self.loop)

    async def fill_remote(self, message):
        if message.remote is not None:
            return
        for ri in self.request_interfaces:
            await ri.fill_remote(message)
            if message.remote is not None:
                message.remote = WrappedRemote(ri, message.remote)
                break
        else:
            raise RuntimeError("No request interface could route message")

    def request(self, request_message, **kwargs):
        immediate_result = RequestProxy()
        async def request():
            try:
                await self.fill_remote(request_message)
                # FIXME: maybe check whether request_interface is
                # actually one of ours
                request_interface = request_message.remote.manager
                request_message.remote = request_message.remote.inner_address
            except Exception as e:
                immediate_result.response.set_exception(e)
                for eb in immediate_result.observation.eb_queue:
                    eb(e)
            else:
                immediate_result.late_init(request_interface.request(request_message, **kwargs))
        self.loop.create_task(request())
        return immediate_result



class RequestProxy(interfaces.Request, BaseUnicastRequest):
    """A helper object created when the result of a request is so unclear that
    the response can not even be created yet. It creates all the futures of a
    request, and forwards results to them from the :meth:`late_init()` call its
    creator promises.

    This helper should go away again in the course of the restructuring towards
    a more protocol-driven response mechanism (possibly something like 'there
    is always only a thin Result, and it is driven however the RequestProvider
    seems fit')."""

    def __init__(self):
        self.response = asyncio.Future()

        self.observation = self.ObservationProxy()

    def late_init(self, real_response):
        real_response.response.add_done_callback(lambda f: self.response.set_exception(f.exception()) if f.exception() else self.response.set_result(f.result()))

        if getattr(real_response, 'observation', None) is not None:
            for cb in self.observation.cb_queue:
                real_response.observation.register_callback(cb)
            for eb in self.observation.eb_queue:
                real_response.observation.register_errback(eb)
            self.observation = real_response.observation

    class ObservationProxy:
        def __init__(self):
            self.cb_queue = []
            self.eb_queue = []

        def register_callback(self, cb):
            self.cb_queue.append(cb)

        def register_errback(self, eb):
            self.eb_queue.append(eb)
