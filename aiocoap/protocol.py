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
import time

from . import defaults
from .credentials import CredentialsMap
from .message import Message
from .messagemanager import MessageManager
from .tokenmanager import TokenManager
from .pipe import Pipe, run_driving_pipe, error_to_message
from . import interfaces
from . import error
from .numbers import (INTERNAL_SERVER_ERROR, NOT_FOUND,
        CONTINUE, OBSERVATION_RESET_TIME)
from .util.asyncio.coro_or_contextmanager import AwaitOrAenter
from .util.asyncio import py38args

import warnings
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


class Context(interfaces.RequestProvider):
    """Applications' entry point to the network

    A :class:`.Context` coordinates one or more network :mod:`.transports`
    implementations and dispatches data between them and the application.

    The application can start requests using the message dispatch methods, and
    set a :class:`resources.Site` that will answer requests directed to the
    application as a server.

    On the library-internals side, it is the prime implementation of the
    :class:`interfaces.RequestProvider` interface, creates :class:`Request` and
    :class:`Response` classes on demand, and decides which transport
    implementations to start and which are to handle which messages.

    **Context creation and destruction**

    The following functions are provided for creating and stopping a context:

    .. note::

        A typical application should only ever create one context, even (or
        especially when) it acts both as a server and as a client (in which
        case a server context should be created).

        A context that is not used any more must be shut down using
        :meth:`.shutdown()`, but typical applications will not need to because
        they use the context for the full process lifetime.

        The context creation functions also work as `asynchronous context
        managers`__, shutting down the (aiocoap) context when the (Python) context
        ends.

        .. __: https://docs.python.org/3/reference/datamodel.html#async-context-managers

    .. automethod:: create_client_context
    .. automethod:: create_server_context

    .. automethod:: shutdown

    **Dispatching messages**

    CoAP requests can be sent using the following functions:

    .. automethod:: request

    .. automethod:: multicast_request

    If more control is needed, you can create a :class:`Request` yourself and
    pass the context to it.


    **Other methods and properties**

    The remaining methods and properties are to be considered unstable even
    when the project reaches a stable version number; please file a feature
    request for stabilization if you want to reliably access any of them.

    (Sorry for the duplicates, still looking for a way to make autodoc list
    everything not already mentioned).

    """
    def __init__(self, loop=None, serversite=None, loggername="coap", client_credentials=None, server_credentials=None):
        self.log = logging.getLogger(loggername)

        self.loop = loop or asyncio.get_event_loop()

        self.serversite = serversite

        self.request_interfaces = []

        self.client_credentials = client_credentials or CredentialsMap()
        self.server_credentials = server_credentials or CredentialsMap()

    #
    # Asynchronous context manager
    #

    async def __aenter__(self):
        # Note that this is usually not called that way; the more common idiom
        # is `async with Context.create_client_context()` which returns a
        # future that also has an __aenter__ method.

        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.shutdown()

    #
    # convenience methods for class instanciation
    #

    async def _append_tokenmanaged_messagemanaged_transport(self, message_interface_constructor):
        tman = TokenManager(self)
        mman = MessageManager(tman)
        transport = await message_interface_constructor(mman)

        mman.message_interface = transport
        tman.token_interface = mman

        self.request_interfaces.append(tman)

    async def _append_tokenmanaged_transport(self, token_interface_constructor):
        tman = TokenManager(self)
        transport = await token_interface_constructor(tman)

        tman.token_interface = transport

        self.request_interfaces.append(tman)

    @classmethod
    @AwaitOrAenter.decorate
    async def create_client_context(cls, *, loggername="coap", loop=None):
        """Create a context bound to all addresses on a random listening port.

        This is the easiest way to get a context suitable for sending client
        requests.

        Note that while this looks in the documentation like a function rather
        than an asynchronous function, it does return an awaitable; the way it
        is set up allows using the result as an asynchronous context manager as
        well.
        """

        if loop is None:
            loop = asyncio.get_event_loop()

        self = cls(loop=loop, serversite=None, loggername=loggername)

        # FIXME make defaults overridable (postponed until they become configurable too)
        for transportname in defaults.get_default_clienttransports(loop=loop):
            if transportname == 'udp6':
                from .transports.udp6 import MessageInterfaceUDP6
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceUDP6.create_client_transport_endpoint(mman, log=self.log, loop=loop))
            elif transportname == 'simple6':
                from .transports.simple6 import MessageInterfaceSimple6
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceSimple6.create_client_transport_endpoint(mman, log=self.log, loop=loop))
            elif transportname == 'tinydtls':
                from .transports.tinydtls import MessageInterfaceTinyDTLS
                await self._append_tokenmanaged_messagemanaged_transport(

                    lambda mman: MessageInterfaceTinyDTLS.create_client_transport_endpoint(mman, log=self.log, loop=loop))
            elif transportname == 'tcpclient':
                from .transports.tcp import TCPClient
                await self._append_tokenmanaged_transport(
                    lambda tman: TCPClient.create_client_transport(tman, self.log, loop))
            elif transportname == 'tlsclient':
                from .transports.tls import TLSClient
                await self._append_tokenmanaged_transport(
                    lambda tman: TLSClient.create_client_transport(tman, self.log, loop, self.client_credentials))
            elif transportname == 'ws':
                from .transports.ws import WSPool
                await self._append_tokenmanaged_transport(
                    lambda tman: WSPool.create_transport(tman, self.log, loop, client_credentials=self.client_credentials))
            elif transportname == 'oscore':
                from .transports.oscore import TransportOSCORE
                oscoretransport = TransportOSCORE(self, self)
                self.request_interfaces.append(oscoretransport)
            else:
                raise RuntimeError("Transport %r not know for client context creation"%transportname)

        return self

    @classmethod
    @AwaitOrAenter.decorate
    async def create_server_context(cls, site, bind=None, *, loggername="coap-server", loop=None, _ssl_context=None, multicast=[], server_credentials=None):
        """Create a context, bound to all addresses on the CoAP port (unless
        otherwise specified in the ``bind`` argument).

        This is the easiest way to get a context suitable both for sending
        client and accepting server requests.

        The ``bind`` argument, if given, needs to be a 2-tuple of IP address
        string and port number, where the port number can be None to use the default port.

        If ``multicast`` is given, it needs to be a list of (multicast address,
        interface name) tuples, which will all be joined. (The IPv4 style of
        selecting the interface by a local address is not supported; users may
        want to use the netifaces package to arrive at an interface name for an
        address).

        As a shortcut, the list may also contain interface names alone. Those
        will be joined for the 'all CoAP nodes' groups of IPv4 and IPv6 (with
        scopes 2 and 5) as well as the respective 'all nodes' groups in IPv6.

        Under some circumstances you may already need a context to pass into
        the site for creation; this is typically the case for servers that
        trigger requests on their own. For those cases, it is usually easiest
        to pass None in as a site, and set the fully constructed site later by
        assigning to the ``serversite`` attribute.
        """

        if loop is None:
            loop = asyncio.get_event_loop()

        self = cls(loop=loop, serversite=site, loggername=loggername, server_credentials=server_credentials)

        multicast_done = not multicast

        for transportname in defaults.get_default_servertransports(loop=loop):
            if transportname == 'udp6':
                from .transports.udp6 import MessageInterfaceUDP6

                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceUDP6.create_server_transport_endpoint(mman, log=self.log, loop=loop, bind=bind, multicast=multicast))
                multicast_done = True
            # FIXME this is duplicated from the client version, as those are client-only anyway
            elif transportname == 'simple6':
                from .transports.simple6 import MessageInterfaceSimple6
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceSimple6.create_client_transport_endpoint(mman, log=self.log, loop=loop))
            elif transportname == 'tinydtls':
                from .transports.tinydtls import MessageInterfaceTinyDTLS

                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceTinyDTLS.create_client_transport_endpoint(mman, log=self.log, loop=loop))
            # FIXME end duplication
            elif transportname == 'tinydtls_server':
                from .transports.tinydtls_server import MessageInterfaceTinyDTLSServer

                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceTinyDTLSServer.create_server(bind, mman, log=self.log, loop=loop, server_credentials=self.server_credentials))
            elif transportname == 'simplesocketserver':
                from .transports.simplesocketserver import MessageInterfaceSimpleServer
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: MessageInterfaceSimpleServer.create_server(bind, mman, log=self.log, loop=loop))
            elif transportname == 'tcpserver':
                from .transports.tcp import TCPServer
                await self._append_tokenmanaged_transport(
                    lambda tman: TCPServer.create_server(bind, tman, self.log, loop))
            elif transportname == 'tcpclient':
                from .transports.tcp import TCPClient
                await self._append_tokenmanaged_transport(
                    lambda tman: TCPClient.create_client_transport(tman, self.log, loop))
            elif transportname == 'tlsserver':
                if _ssl_context is not None:
                    from .transports.tls import TLSServer
                    await self._append_tokenmanaged_transport(
                        lambda tman: TLSServer.create_server(bind, tman, self.log, loop, _ssl_context))
            elif transportname == 'tlsclient':
                from .transports.tls import TLSClient
                await self._append_tokenmanaged_transport(
                    lambda tman: TLSClient.create_client_transport(tman, self.log, loop, self.client_credentials))
            elif transportname == 'ws':
                from .transports.ws import WSPool
                await self._append_tokenmanaged_transport(
                    # None, None: Unlike the other transports this has a server/client generic creator, and only binds if there is some bind
                    lambda tman: WSPool.create_transport(tman, self.log, loop, client_credentials=self.client_credentials, server_bind=bind or (None, None), server_context=_ssl_context))
            elif transportname == 'oscore':
                from .transports.oscore import TransportOSCORE
                oscoretransport = TransportOSCORE(self, self)
                self.request_interfaces.append(oscoretransport)
            else:
                raise RuntimeError("Transport %r not know for server context creation"%transportname)

        if not multicast_done:
            self.log.warning("Multicast was requested, but no multicast capable transport was selected.")

        return self

    async def shutdown(self):
        """Take down any listening sockets and stop all related timers.

        After this coroutine terminates, and once all external references to
        the object are dropped, it should be garbage-collectable.

        This method may take the time to inform communications partners of
        stopped observations (but currently does not)."""

        self.log.debug("Shutting down context")

        done, pending = await asyncio.wait([
                asyncio.create_task(
                    ri.shutdown(),
                    **py38args(name="Shutdown of %r" % ri)
                    )
                for ri
                in self.request_interfaces],
            timeout=3)
        for item in done:
            await item

    # FIXME: determine how official this should be, or which part of it is
    # public -- now that BlockwiseRequest uses it. (And formalize what can
    # change about messages and what can't after the remote has been thusly
    # populated).
    async def find_remote_and_interface(self, message):
        for ri in self.request_interfaces:
            if await ri.fill_or_recognize_remote(message):
                return ri
        raise RuntimeError("No request interface could route message")

    def request(self, request_message, handle_blockwise=True):
        if handle_blockwise:
            return BlockwiseRequest(self, request_message)

        pipe = Pipe(request_message, self.log)
        # Request sets up callbacks at creation
        result = Request(pipe, self.loop, self.log)

        async def send():
            try:
                request_interface = await self.find_remote_and_interface(request_message)
                request_interface.request(pipe)
            except Exception as e:
                pipe.add_exception(e)
                return
        self.loop.create_task(
                send(),
                **py38args(name="Request processing of %r" % result)
                )
        return result

    # the following are under consideration for moving into Site or something
    # mixed into it

    def render_to_pipe(self, pipe):
        """Fill a pipe by running the site's render_to_pipe interface and
        handling errors."""

        pr_that_can_receive_errors = error_to_message(pipe, self.log)

        run_driving_pipe(
                pr_that_can_receive_errors,
                self._render_to_pipe(pipe),
                name="Rendering for %r" % pipe.request,
                )

    async def _render_to_pipe(self, pipe):
        if self.serversite is None:
            pipe.add_response(Message(code=NOT_FOUND, payload=b"not a server"), is_last=True)
            return

        return await self.serversite.render_to_pipe(pipe)

class BaseRequest(object):
    """Common mechanisms of :class:`Request` and :class:`MulticastRequest`"""

class BaseUnicastRequest(BaseRequest):
    """A utility class that offers the :attr:`response_raising` and
    :attr:`response_nonraising` alternatives to waiting for the
    :attr:`response` future whose error states can be presented either as an
    unsuccessful response (eg. 4.04) or an exception.

    It also provides some internal tools for handling anything that has a
    :attr:`response` future and an :attr:`observation`"""

    @property
    async def response_raising(self):
        """An awaitable that returns if a response comes in and is successful,
        otherwise raises generic network exception or a
        :class:`.error.ResponseWrappingError` for unsuccessful responses.

        Experimental Interface."""

        response = await self.response
        if not response.code.is_successful():
            raise error.ResponseWrappingError(response)

        return response

    @property
    async def response_nonraising(self):
        """An awaitable that rather returns a 500ish fabricated message (as a
        proxy would return) instead of raising an exception.

        Experimental Interface."""

        # FIXME: Can we smuggle error_to_message into the underlying pipe?
        # That should make observe notifications into messages rather
        # than exceptions as well, plus it has fallbacks for `e.to_message()`
        # raising.

        try:
            return await self.response
        except error.RenderableError as e:
            return e.to_message()
        except Exception:
            return Message(code=INTERNAL_SERVER_ERROR)

class Request(interfaces.Request, BaseUnicastRequest):

    # FIXME: Implement timing out with REQUEST_TIMEOUT here

    def __init__(self, pipe, loop, log):
        self._pipe = pipe

        self.response = loop.create_future()

        if pipe.request.opt.observe == 0:
            self.observation = ClientObservation()
        else:
            self.observation = None

        self._runner = self._run()
        self._runner.send(None)
        def process(event):
            try:
                self._runner.send(event)
                return True
            except StopIteration:
                return False
        self._stop_interest = self._pipe.on_event(process)

        self.log = log

        self.response.add_done_callback(self._response_cancellation_handler)

    def _response_cancellation_handler(self, response):
        # Propagate cancellation to the runner (if interest in the first
        # response is lost, there won't be observation items to pull out), but
        # not general completion (because if it's completed and not cancelled,
        # eg. when an observation is active)
        if self.response.cancelled() and self._runner is not None:
            # Dropping the only reference makes it stop with GeneratorExit,
            # similar to a cancelled task
            self._runner = None
            self._stop_interest()
        # But either way we won't be calling _stop_interest any more, so let's
        # not keep anything referenced
        self._stop_interest = None

    @staticmethod
    def _add_response_properties(response, request):
        response.request = request

    def _run(self):
        # FIXME: This is in iterator form because it used to be a task that
        # awaited futures, and that code could be easily converted to an
        # iterator. I'm not sure that's a bad state here, but at least it
        # should be a more conscious decision to make this an iterator rather
        # than just having it happen to be one.
        #
        # FIXME: check that responses come from the same remmote as long as we're assuming unicast

        first_event = yield None

        if first_event.message is not None:
            self._add_response_properties(first_event.message, self._pipe.request)
            self.response.set_result(first_event.message)
        else:
            self.response.set_exception(first_event.exception)
            if not isinstance(first_event.exception, error.Error):
                self.log.warning(
                       "An exception that is not an aiocoap Error was raised "
                       "from a transport; please report this as a bug in "
                       "aiocoap: %r", first_event.exception)

        if self.observation is None:
            if not first_event.is_last:
                self.log.error("Pipe indicated more possible responses"
                               " while the Request handler would not know what to"
                               " do with them, stopping any further request.")
                self._pipe.stop_interest()
            return

        if first_event.is_last:
            self.observation.error(error.NotObservable())
            return

        if first_event.message.opt.observe is None:
            self.log.error("Pipe indicated more possible responses"
                           " while the Request handler would not know what to"
                           " do with them, stopping any further request.")
            self._pipe.stop_interest()
            return

        # variable names from RFC7641 Section 3.4
        v1 = first_event.message.opt.observe
        t1 = time.time()

        while True:
            # We don't really support cancellation of observations yet (see
            # https://github.com/chrysn/aiocoap/issues/92), but at least
            # stopping the interest is a way to free the local resources after
            # the first observation update, and to make the MID handler RST the
            # observation on the next.
            # FIXME: there *is* now a .on_cancel callback, we should at least
            # hook into that, and possibly even send a proper cancellation
            # then.
            next_event = yield True
            if self.observation.cancelled:
                self._pipe.stop_interest()
                return

            if next_event.exception is not None:
                self.observation.error(next_event.exception)
                if not next_event.is_last:
                    self._pipe.stop_interest()
                if not isinstance(next_event.exception, error.Error):
                    self.log.warning(
                           "An exception that is not an aiocoap Error was "
                           "raised from a transport during an observation; "
                           "please report this as a bug in aiocoap: %r",
                           next_event.exception)
                return

            self._add_response_properties(next_event.message, self._pipe.request)

            if next_event.message.opt.observe is not None:
                # check for reordering
                v2 = next_event.message.opt.observe
                t2 = time.time()

                is_recent = (v1 < v2 and v2 - v1 < 2**23) or \
                        (v1 > v2 and v1 - v2 > 2**23) or \
                        (t2 > t1 + OBSERVATION_RESET_TIME)
                if is_recent:
                    t1 = t2
                    v1 = v2
            else:
                # the terminal message is always the last
                is_recent = True

            if is_recent:
                self.observation.callback(next_event.message)

            if next_event.is_last:
                self.observation.error(error.ObservationCancelled())
                return

            if next_event.message.opt.observe is None:
                self.observation.error(error.ObservationCancelled())
                self.log.error("Pipe indicated more possible responses"
                               " while the Request handler would not know what to"
                               " do with them, stopping any further request.")
                self._pipe.stop_interest()
                return


class BlockwiseRequest(BaseUnicastRequest, interfaces.Request):
    def __init__(self, protocol, app_request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("blockwise-requester")

        self.response = protocol.loop.create_future()

        if app_request.opt.observe is not None:
            self.observation = ClientObservation()
        else:
            self.observation = None

        self._runner = protocol.loop.create_task(self._run_outer(
            app_request,
            self.response,
            weakref.ref(self.observation) if self.observation is not None else lambda: None,
            self.protocol,
            self.log,
            ),
            **py38args(name="Blockwise runner for %r" % app_request))
        self.response.add_done_callback(self._response_cancellation_handler)

    def _response_cancellation_handler(self, response_future):
        # see Request._response_cancellation_handler
        if self.response.cancelled():
            self._runner.cancel()

    @classmethod
    async def _run_outer(cls, app_request, response, weak_observation, protocol, log):
        try:
            await cls._run(app_request, response, weak_observation, protocol, log)
        except asyncio.CancelledError:
            pass # results already set
        except Exception as e:
            logged = False
            if not response.done():
                logged = True
                response.set_exception(e)
            obs = weak_observation()
            if app_request.opt.observe is not None and obs is not None:
                logged = True
                obs.error(e)
            if not logged:
                # should be unreachable
                log.error("Exception in BlockwiseRequest runner neither went to response nor to observation: %s", e, exc_info=e)

    # This is a class method because that allows self and self.observation to
    # be freed even when this task is running, and the task to stop itself --
    # otherwise we couldn't know when users just "forget" about a request
    # object after using its response (esp. in observe cases) and leave this
    # task running.
    @classmethod
    async def _run(cls, app_request, response, weak_observation, protocol, log):
        # we need to populate the remote right away, because the choice of
        # blocks depends on it.
        await protocol.find_remote_and_interface(app_request)

        size_exp = app_request.remote.maximum_block_size_exp

        if app_request.opt.block1 is not None:
            assert app_request.opt.block1.block_number == 0, "Unexpected block number in app_request"
            assert not app_request.opt.block1.more, "Unexpected more-flag in app_request"
            # this is where the library user can traditionally pass in size
            # exponent hints into the library.
            size_exp = app_request.opt.block1.size_exponent

        # Offset in the message in blocks of size_exp. Whoever changes size_exp
        # is responsible for updating this number.
        block_cursor = 0

        while True:
            # ... send a chunk

            if size_exp >= 6:
                # FIXME from maximum_payload_size
                fragmentation_threshold = app_request.remote.maximum_payload_size
            else:
                fragmentation_threshold = (2 ** (size_exp + 4))

            if app_request.opt.block1 is not None or \
                    len(app_request.payload) > fragmentation_threshold:
                current_block1 = app_request._extract_block(
                        block_cursor,
                        size_exp,
                        app_request.remote.maximum_payload_size)
            else:
                current_block1 = app_request

            blockrequest = protocol.request(current_block1, handle_blockwise=False)
            blockresponse = await blockrequest.response

            # store for future blocks to ensure that the next blocks will be
            # sent from the same source address (in the UDP case; for many
            # other transports it won't matter).
            app_request.remote = blockresponse.remote

            if blockresponse.opt.block1 is None:
                if blockresponse.code.is_successful() and current_block1.opt.block1:
                    log.warning("Block1 option completely ignored by server, assuming it knows what it is doing.")
                # FIXME: handle 4.13 and retry with the indicated size option
                break

            block1 = blockresponse.opt.block1
            log.debug("Response with Block1 option received, number = %d, more = %d, size_exp = %d.", block1.block_number, block1.more, block1.size_exponent)

            if block1.block_number != current_block1.opt.block1.block_number:
                raise error.UnexpectedBlock1Option("Block number mismatch")

            if size_exp == 7:
                block_cursor += len(current_block1.payload) // 1024
            else:
                block_cursor += 1

            while block1.size_exponent < size_exp:
                block_cursor *= 2
                size_exp -= 1

            if not current_block1.opt.block1.more:
                if block1.more or blockresponse.code == CONTINUE:
                    # treating this as a protocol error -- letting it slip
                    # through would misrepresent the whole operation as an
                    # over-all 2.xx (successful) one.
                    raise error.UnexpectedBlock1Option("Server asked for more data at end of body")
                break

            # checks before preparing the next round:

            if blockresponse.opt.observe:
                # we're not *really* interested in that block, we just sent an
                # observe option to indicate that we'll want to observe the
                # resulting representation as a whole
                log.warning("Server answered Observe in early Block1 phase, cancelling the erroneous observation.")
                blockrequest.observe.cancel()

            if block1.more:
                # FIXME i think my own server is dowing this wrong
                #if response.code != CONTINUE:
                #    raise error.UnexpectedBlock1Option("more-flag set but no Continue")
                pass
            else:
                if not blockresponse.code.is_successful():
                    break
                else:
                    # ignoring (discarding) the successul intermediate result, waiting for a final one
                    continue

        lower_observation = None
        if app_request.opt.observe is not None:
            if blockresponse.opt.observe is not None:
                lower_observation = blockrequest.observation
            else:
                obs = weak_observation()
                if obs:
                    obs.error(error.NotObservable())
                del obs

        assert blockresponse is not None, "Block1 loop broke without setting a response"
        blockresponse.opt.block1 = None

        # FIXME check with RFC7959: it just says "send requests similar to the
        # requests in the Block1 phase", what does that mean? using the last
        # block1 as a reference for now, especially because in the
        # only-one-request-block case, that's the original request we must send
        # again and again anyway
        assembled_response = await cls._complete_by_requesting_block2(protocol, current_block1, blockresponse, log)

        response.set_result(assembled_response)
        # finally set the result

        if lower_observation is not None:
            # FIXME this can all be simplified a lot since it's no more
            # expected that observations shut themselves down when GC'd.
            obs = weak_observation()
            del weak_observation
            if obs is None:
                lower_observation.cancel()
                return
            future_weak_observation = protocol.loop.create_future() # packing this up because its destroy callback needs to reference the subtask
            subtask = asyncio.create_task(
                    cls._run_observation(
                        app_request,
                        lower_observation,
                        future_weak_observation,
                        protocol,
                        log),
                    **py38args(name="Blockwise observation for %r" % app_request)
                    )
            future_weak_observation.set_result(weakref.ref(obs, lambda obs: subtask.cancel()))
            obs.on_cancel(subtask.cancel)
            del obs
            await subtask

    @classmethod
    async def _run_observation(cls, original_request, lower_observation, future_weak_observation, protocol, log):
        weak_observation = await future_weak_observation
        # we can use weak_observation() here at any time, because whenever that
        # becomes None, this task gets cancelled
        try:
            async for block1_notification in lower_observation:
                log.debug("Notification received")
                full_notification = await cls._complete_by_requesting_block2(protocol, original_request, block1_notification, log)
                log.debug("Reporting completed notification")
                weak_observation().callback(full_notification)
            # FIXME verify that this loop actually ends iff the observation
            # was cancelled -- otherwise find out the cause(s) or make it not
            # cancel under indistinguishable circumstances
            weak_observation().error(error.ObservationCancelled())
        except asyncio.CancelledError:
            return
        except Exception as e:
            weak_observation().error(e)

    @classmethod
    async def _complete_by_requesting_block2(cls, protocol, request_to_repeat, initial_response, log):
        # FIXME this can probably be deduplicated against BlockwiseRequest

        if initial_response.opt.block2 is None or initial_response.opt.block2.more is False:
            initial_response.opt.block2 = None
            return initial_response

        if initial_response.opt.block2.block_number != 0:
            log.error("Error assembling blockwise response (expected first block)")
            raise error.UnexpectedBlock2()

        assembled_response = initial_response
        last_response = initial_response
        while True:
            current_block2 = request_to_repeat._generate_next_block2_request(assembled_response)

            current_block2 = current_block2.copy(remote=initial_response.remote)

            blockrequest = protocol.request(current_block2, handle_blockwise=False)
            last_response = await blockrequest.response

            if last_response.opt.block2 is None:
                log.warning("Server sent non-blockwise response after having started a blockwise transfer. Blockwise transfer cancelled, accepting single response.")
                return last_response

            block2 = last_response.opt.block2
            log.debug("Response with Block2 option received, number = %d, more = %d, size_exp = %d.", block2.block_number, block2.more, block2.size_exponent)
            try:
                assembled_response._append_response_block(last_response)
            except error.Error as e:
                log.error("Error assembling blockwise response, passing on error %r", e)
                raise

            if block2.more is False:
                return assembled_response

class ClientObservation:
    """An interface to observe notification updates arriving on a request.

    This class does not actually provide any of the observe functionality, it
    is purely a container for dispatching the messages via callbacks or
    asynchronous iteration. It gets driven (ie. populated with responses or
    errors including observation termination) by a Request object.
    """
    def __init__(self):
        self.callbacks = []
        self.errbacks = []

        self.cancelled = False
        self._on_cancel = []

        self._latest_response = None
        # the analogous error is stored in _cancellation_reason when cancelled.

    def __aiter__(self):
        """`async for` interface to observations. Currently, this still loses
        information to the application (the reason for the termination is
        unclear).

        Experimental Interface."""
        it = self._Iterator()
        self.register_callback(it.push)
        self.register_errback(it.push_err)
        return it

    class _Iterator:
        def __init__(self):
            self._future = asyncio.get_event_loop().create_future()

        def push(self, item):
            if self._future.done():
                # we don't care whether we overwrite anything, this is a lossy queue as observe is lossy
                self._future = asyncio.get_event_loop().create_future()
            self._future.set_result(item)

        def push_err(self, e):
            if self._future.done():
                self._future = asyncio.get_event_loop().create_future()
            self._future.set_exception(e)

        async def __anext__(self):
            f = self._future
            try:
                result = await self._future
                # FIXME see `await servobs._trigger` comment: might waiting for
                # the original future not yield the first future's result when
                # a quick second future comes in in a push?
                if f is self._future:
                    self._future = asyncio.get_event_loop().create_future()
                return result
            except (error.NotObservable, error.ObservationCancelled):
                # only exit cleanly when the server -- right away or later --
                # states that the resource is not observable any more
                # FIXME: check whether an unsuccessful message is still passed
                # as an observation result (or whether it should be)
                raise StopAsyncIteration

        def __del__(self):
            if self._future.done():
                try:
                    # Fetch the result so any errors show up at least in the
                    # finalizer output
                    self._future.result()
                except (error.ObservationCancelled, error.NotObservable):
                    # This is the case at the end of an observation cancelled
                    # by the server.
                    pass
                except (error.LibraryShutdown, asyncio.CancelledError):
                    pass

    def register_callback(self, callback):
        """Call the callback whenever a response to the message comes in, and
        pass the response to it."""
        if self.cancelled:
            return

        self.callbacks.append(callback)
        if self._latest_response is not None:
            callback(self._latest_response)

    def register_errback(self, callback):
        """Call the callback whenever something goes wrong with the
        observation, and pass an exception to the callback. After such a
        callback is called, no more callbacks will be issued."""
        if self.cancelled:
            callback(self._cancellation_reason)
            return
        self.errbacks.append(callback)

    def callback(self, response):
        """Notify all listeners of an incoming response"""

        self._latest_response = response

        for c in self.callbacks:
            c(response)

    def error(self, exception):
        """Notify registered listeners that the observation went wrong. This
        can only be called once."""

        for c in self.errbacks:
            c(exception)

        self.cancel()
        self._cancellation_reason = exception

    def cancel(self):
        # FIXME determine whether this is called by anything other than error,
        # and make it private so there is always a _cancellation_reason
        """Cease to generate observation or error events. This will not
        generate an error by itself."""

        assert not self.cancelled

        # make sure things go wrong when someone tries to continue this
        self.errbacks = None
        self.callbacks = None

        self.cancelled = True
        while self._on_cancel:
            self._on_cancel.pop()()

        self._cancellation_reason = None

    def on_cancel(self, callback):
        if self.cancelled:
            callback()
        self._on_cancel.append(callback)

    def __repr__(self):
        return '<%s %s at %#x>'%(type(self).__name__, "(cancelled)" if self.cancelled else "(%s call-, %s errback(s))"%(len(self.callbacks), len(self.errbacks)), id(self))

class ServerObservation:
    def __init__(self):
        self._accepted = False
        self._trigger = asyncio.get_event_loop().create_future()
        # A deregistration is "early" if it happens before the response message
        # is actually sent; calling deregister() in that time (typically during
        # `render()`) will not send an unsuccessful response message but just
        # sent this flag which is set to None as soon as it is too late for an
        # early deregistration.
        # This mechanism is temporary until more of aiocoap behaves like
        # Pipe which does not suffer from this limitation.
        self._early_deregister = False
        self._late_deregister = False

    def accept(self, cancellation_callback):
        self._accepted = True
        self._cancellation_callback = cancellation_callback

    def deregister(self, reason=None):
        if self._early_deregister is False:
            self._early_deregister = True
            return

        warnings.warn("Late use of ServerObservation.deregister() is"
                      " deprecated, use .trigger with an unsuccessful value"
                      " instead",
                      DeprecationWarning)
        self.trigger(Message(code=INTERNAL_SERVER_ERROR, payload=b"Resource became unobservable"))

    def trigger(self, response=None, *, is_last=False):
        """Send an updated response; if None is given, the observed resource's
        rendering will be invoked to produce one.

        `is_last` can be set to True to indicate that no more responses will be
        sent. Note that an unsuccessful response will be the last no matter
        what is_last says, as such a message always terminates a CoAP
        observation."""
        if is_last:
            self._late_deregister = True
        if self._trigger.done():
            # we don't care whether we overwrite anything, this is a lossy queue as observe is lossy
            self._trigger = asyncio.get_event_loop().create_future()
        self._trigger.set_result(response)
