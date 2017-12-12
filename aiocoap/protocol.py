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
import functools
import weakref
import time

from . import defaults
from .credentials import CredentialsMap
from .message import Message
from .messagemanager import MessageManager
from .tokenmanager import TokenManager, PlumbingRequest
from . import interfaces
from . import error
from .numbers import (COAP_PORT, DEFAULT_BLOCK_SIZE_EXP, INTERNAL_SERVER_ERROR,
        SERVICE_UNAVAILABLE, CONTENT, OBSERVATION_RESET_TIME)

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

    Currently, only one network transport is created, and the details of the
    messaging layer of CoAP are managed in this class. It is expected that much
    of the functionality will be moved into transports at latest when CoAP over
    TCP and websockets is implemented.

    **Context creation and destruction**

    The following functions are provided for creating and stopping a context:

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
    def __init__(self, loop=None, serversite=None, loggername="coap", client_credentials=None):
        self.log = logging.getLogger(loggername)

        self.loop = loop or asyncio.get_event_loop()

        self.serversite = serversite

        self.request_interfaces = []

        self._running_renderings = set()

        self.client_credentials = client_credentials or CredentialsMap()

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
            if transportname == 'udp6':
                from .transports.udp6 import TransportEndpointUDP6
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: TransportEndpointUDP6.create_client_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to))
            elif transportname == 'simple6':
                from .transports.simple6 import TransportEndpointSimple6
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: TransportEndpointSimple6.create_client_transport_endpoint(mman, log=self.log, loop=loop))
                # FIXME warn if dump_to is not None
            elif transportname == 'tinydtls':
                from .transports.tinydtls import TransportEndpointTinyDTLS
                await self._append_tokenmanaged_messagemanaged_transport(

                    lambda mman: TransportEndpointTinyDTLS.create_client_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to))
            else:
                raise RuntimeError("Transport %r not know for client context creation"%transportname)

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
            if transportname == 'udp6':
                from .transports.udp6 import TransportEndpointUDP6

                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: TransportEndpointUDP6.create_server_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to, bind=bind))
            # FIXME this is duplicated from the client version, as those are client-only anyway
            elif transportname == 'simple6':
                from .transports.simple6 import TransportEndpointSimple6
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: TransportEndpointSimple6.create_client_transport_endpoint(mman, log=self.log, loop=loop))
                # FIXME warn if dump_to is not None
            elif transportname == 'tinydtls':
                from .transports.tinydtls import TransportEndpointTinyDTLS

                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: TransportEndpointTinyDTLS.create_client_transport_endpoint(mman, log=self.log, loop=loop, dump_to=dump_to))
            # FIXME end duplication
            elif transportname == 'simplesocketserver':
                # FIXME dump_to not implemented
                from .transports.simplesocketserver import TransportEndpointSimpleServer
                await self._append_tokenmanaged_messagemanaged_transport(
                    lambda mman: TransportEndpointSimpleServer.create_server(bind, mman, log=self.log, loop=loop))
            else:
                raise RuntimeError("Transport %r not know for server context creation"%transportname)

        return self

    async def shutdown(self):
        for r in self._running_renderings:
            r.cancel()

        await asyncio.wait([ri.shutdown() for ri in self.request_interfaces], timeout=3, loop=self.loop)

    async def find_remote_and_interface(self, message):
        for ri in self.request_interfaces:
            if await ri.fill_or_recognize_remote(message):
                return ri
        raise RuntimeError("No request interface could route message")

    def request(self, request_message, handle_blockwise=True):
        if handle_blockwise:
            return BlockwiseRequest(self, request_message)

        plumbing_request = PlumbingRequest(request_message)
        result = Request(plumbing_request, self.loop)

        async def send():
            try:
                request_interface = await self.find_remote_and_interface(request_message)
            except Exception as e:
                plumbing_request.add_exception(e)
                return
            request_interface.request(plumbing_request)
        self.loop.create_task(send())
        return result

    def render_to_plumbing_request(self, plumbing_request):
        """Satisfy a plumbing request from the full :meth:`render` /
        :meth:`needs_blockwise_assembly` / :meth:`add_observation` interfaces
        provided by the site."""

        task = self.loop.create_task(
                self._render_to_plumbing_request(plumbing_request))
        self._running_renderings.add(task)
        remove_task = functools.partial(self._running_renderings.remove, task)
        task.add_done_callback(lambda result, cb=remove_task: cb())

    async def _render_to_plumbing_request(self, plumbing_request):
        # will receive a result in the finally, so the observation's
        # cancellation callback can just be hooked into that rather than
        # catching CancellationError here
        cancellation_future = asyncio.Future()

        try:
            await self._render_to_plumbing_request_inner(plumbing_request,
                    cancellation_future)
        except error.RenderableError as e:
            # the repr() here is quite imporant for garbage collection
            self.log.info("Render request raised a renderable error (%s), responding accordingly.", repr(e))
            plumbing_request.add_response(e.to_message(), is_last=True)
        except asyncio.CancelledError:
            self.log.info("Rendering was interrupted, informing client")
            plumbing_request.add_response(Message(code=SERVICE_UNAVAILABLE), is_last=True)
            raise
        except Exception as e:
            plumbing_request.add_response(Message(code=INTERNAL_SERVER_ERROR), is_last=True)
            self.log.error("An exception occurred while rendering a resource: %r", e, exc_info=e)
        finally:
            cancellation_future.set_result(None)


    async def _render_to_plumbing_request_inner(self, plumbing_request, cancellation_future):
        request = plumbing_request.request
        blockwise = await self.serversite.needs_blockwise_assembly(request)
        if blockwise:
            # FIXME
            self.log.warning(
                "Resource requests blockwise reassembly, but context can't"
                " serve that yet")

        observe_requested = request.opt.observe == 0
        if observe_requested:
            servobs = ServerObservation()
            await self.serversite.add_observation(request, servobs)

            if servobs._accepted:
                cancellation_future.add_done_callback(
                        lambda f, cb=servobs._cancellation_callback: cb())

        response = await self.serversite.render(request)
        if response.code is None:
            response.code = CONTENT
        if not response.code.is_response():
            self.log.warning("Response does not carry response code (%r),"
                             " application probably violates protocol.",
                             response.code)

        can_continue = observe_requested and servobs._accepted and \
                response.code.is_successful()
        if can_continue:
            response.opt.observe = next_observation_number =0
        plumbing_request.add_response(response, is_last=not can_continue)

        while can_continue:
            await servobs._trigger
            # fetched in a separate step: i'm not sure whether the future
            # switching in .trigger() might not make the first result appear
            # here
            response = servobs._trigger.result()
            servobs._trigger = asyncio.Future()

            if response is None:
                response = await self.serversite.render(request)
            if response.code is None:
                response.code = CONTENT

            can_continue = response.code.is_successful()

            if can_continue:
                ## @TODO handle situations in which this gets called more often than
                #        2^32 times in 256 seconds (or document why we can be sure that
                #        that will not happen)
                next_observation_number = next_observation_number + 1
                response.opt.observe = next_observation_number

            plumbing_request.add_response(response, is_last=not can_continue)

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

        try:
            return await self.response
        except error.RenderableError:
            return e.to_message()
        except Exception as e:
            return Message(code=INTERNAL_SERVER_ERROR)

class Request(interfaces.Request, BaseUnicastRequest):

    # FIXME: Implement timing out with REQUEST_TIMEOUT here

    def __init__(self, plumbing_request, loop):
        self._plumbing_request = plumbing_request

        self.response = asyncio.Future()

        if plumbing_request.request.opt.observe == 0:
            self.observation = ClientObservation()
        else:
            self.observation = None

        loop.create_task(self._run())

    @staticmethod
    def _add_response_properties(response, request):
        # whether it's suitable here to use unresolved_remote is doubtful -- it
        # was the *intention* of the user to get that URL, but the server would
        # be none the wiser. (if it's not set, the client gets the ip literal
        # when inspecting the response's uri, which would have worked as well.
        # for dtls, even though not implemented yet, that information would be
        # filled from the SNI host name.)
        response.requested_hostinfo = request.opt.uri_host or request.unresolved_remote
        response.requested_path = request.opt.uri_path
        response.requested_query = request.opt.uri_query

    async def _run(self):
        # FIXME: check that responses come from the same remmote as long as we're assuming unicast

        first_event = await self._plumbing_request._events.get()

        if first_event.message is not None:
            self._add_response_properties(first_event.message, self._plumbing_request.request)
            self.response.set_result(first_event.message)
        else:
            self.response.set_exception(first_event.exception)

        if self.observation is None:
            if not first_event.is_last:
                self.log.error("PlumbingRequest indicated more possible responses"
                               " while the Request handler would not know what to"
                               " do with them, stopping any further request.")
                self._plumbing_request.stop_interest()
            return

        if first_event.is_last:
            self.observation.error(error.NotObservable())
            return

        if first_event.message.opt.observe is None:
            self.log.error("PlumbingRequest indicated more possible responses"
                           " while the Request handler would not know what to"
                           " do with them, stopping any further request.")
            self._plumbing_request.stop_interest()
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
            next_event = await self._plumbing_request._events.get()
            if self.observation.cancelled:
                self._plumbing_request.stop_interest()
                return

            if next_event.exception is not None:
                self.observation.error(next_event.exception)
                if not next_event.is_last:
                    self._plumbing_request.stop_interest()
                return

            self._add_response_properties(next_event.message, self._plumbing_request.request)

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
                self.log.error("PlumbingRequest indicated more possible responses"
                               " while the Request handler would not know what to"
                               " do with them, stopping any further request.")
                self._plumbing_request.stop_interest()
                return


class BlockwiseRequest(BaseUnicastRequest, interfaces.Request):
    def __init__(self, protocol, app_request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("blockwise-requester")

        self.response = asyncio.Future()

        if app_request.opt.observe is not None:
            self.observation = ClientObservation()
        else:
            self.observation = None

        self._runner = asyncio.Task(self._run_outer(
            app_request,
            self.response,
            weakref.ref(self.observation) if self.observation is not None else lambda: None,
            self.protocol,
            self.log,
            ))
        self.response.add_done_callback(self._response_cancellation_handler)

    def _response_cancellation_handler(self, response_future):
        if self.response.cancelled() and not self._runner.cancelled():
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
        size_exp = DEFAULT_BLOCK_SIZE_EXP

        if app_request.opt.block1 is not None:
            assert app_request.opt.block1.block_number == 0, "Unexpected block number in app_request"
            assert app_request.opt.block1.more == False, "Unexpected more-flag in app_request"
            size_exp = app_request.opt.block1.size_exponent

        # Offset in the message in blocks of size_exp. Whoever changes size_exp
        # is responsible for updating this number.
        block_cursor = 0

        remote = None

        while True:
            # ... send a chunk

            if len(app_request.payload) > (2 ** (size_exp + 4)):
                current_block1 = app_request._extract_block(block_cursor, size_exp)
            else:
                current_block1 = app_request

            if remote is not None:
                current_block1 = current_block1.copy(remote=remote)

            blockrequest = protocol.request(current_block1, handle_blockwise=False)
            blockresponse = await blockrequest.response

            # store for future blocks: don't resolve the address again
            remote = blockresponse.remote

            if blockresponse.opt.block1 is None:
                if blockresponse.code.is_successful() and current_block1.opt.block1:
                    log.warning("Block1 option completely ignored by server, assuming it knows what it is doing.")
                # FIXME: handle 4.13 and retry with the indicated size option
                break

            block1 = blockresponse.opt.block1
            log.debug("Response with Block1 option received, number = %d, more = %d, size_exp = %d.", block1.block_number, block1.more, block1.size_exponent)

            if block1.block_number != current_block1.opt.block1.block_number:
                raise error.UnexpectedBlock1Option("Block number mismatch")

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
            future_weak_observation = asyncio.Future() # packing this up because its destroy callback needs to reference the subtask
            subtask = asyncio.Task(cls._run_observation(app_request, lower_observation, future_weak_observation, protocol, log))
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
        except asyncio.CancelledError:
            return
        except StopAsyncIteration:
            # FIXME verify that this loop actually ends iff the observation
            # was cancelled -- otherwise find out the cause(s) or make it not
            # cancel under indistinguishable circumstances
            weak_observation().error(error.ObservationCancelled())
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
            raise UnexpectedBlock2()

        assembled_response = initial_response
        last_response = initial_response
        while True:
            current_block2 = request_to_repeat._generate_next_block2_request(last_response)

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
                log.error("Error assembling blockwise response, passing on error %r"%e)
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
            self._future = asyncio.Future()

        def push(self, item):
            if self._future.done():
                # we don't care whether we overwrite anything, this is a lossy queue as observe is lossy
                self._future = asyncio.Future()
            self._future.set_result(item)

        def push_err(self, e):
            if self._future.done():
                self._future = asyncio.Future()
            self._future.set_exception(e)

        async def __anext__(self):
            f = self._future
            try:
                result = await self._future
                # FIXME see `await servobs._trigger` comment: might waiting for
                # the original future not yield the first future's result when
                # a quick second future comes in in a push?
                if f is self._future:
                    self._future = asyncio.Future()
                return result
            except (error.NotObservable, error.ObservationCancelled):
                # only exit cleanly when the server -- right away or later --
                # states that the resource is not observable any more
                # FIXME: check whether an unsuccessful message is still passed
                # as an observation result (or whether it should be)
                raise StopAsyncIteration

    def register_callback(self, callback):
        """Call the callback whenever a response to the message comes in, and
        pass the response to it."""
        if self.cancelled:
            return
        self.callbacks.append(callback)

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

        assert self.cancelled == False

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
        self._trigger = asyncio.Future()

    def accept(self, cancellation_callback):
        self._accepted = True
        self._cancellation_callback = cancellation_callback

    def deregister(self):
        warnings.warn("ServerObservation.deregister() is deprecated, use"
                      " .trigger with an unsuccessful value instead",
                      warnings.DeprecationWarning)
        self.trigger(Message(code=INTERNAL_SERVER_ERROR, payload=b"Resource became unobservable"))

    def trigger(self, response=None):
        if self._trigger.done():
            # we don't care whether we overwrite anything, this is a lossy queue as observe is lossy
            self._trigger = asyncio.Future()
        self._trigger.set_result(response)
