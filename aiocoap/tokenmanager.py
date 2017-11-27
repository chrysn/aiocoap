# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
from collections import namedtuple
import functools
import logging
import os
import random
import weakref

from . import error
from . import interfaces
from .message import Message, NoResponse
from .numbers import *
from .optiontypes import BlockOption
from .util.asyncio import AsyncGenerator
from .util import hostportjoin

class TokenManager(interfaces.RequestProvider, interfaces.TokenManager):
    def __init__(self, context):
        self.context = context

        self.token = random.randint(0, 65535)
        self.outgoing_requests = {}  #: Unfinished outgoing requests (identified by token and remote)
        self.incoming_requests = {}  #: Unfinished incoming requests. ``(path-tuple, remote): Request``

        self.log = self.context.log
        self.loop = self.context.loop

        #self.token_interface = … -- needs to be set post-construction, because the token_interface in its constructor already needs to get its manager

    @property
    def client_credentials(self):
        return self.context.client_credentials

    async def shutdown(self):
        for request in self.outoging_requests:
            request.add_exception(error.LibraryShutdown())
        self.outgoing_requests = None

        await self.token_interface.shutdown()


    def kill_transactions(self, remote, exception=error.CommunicationKilled):
        """Abort all pending exchanges and observations to a given remote.

        The exact semantics of this are not yet completely frozen -- currently,
        pending exchanges are treated as if they timeouted, server sides of
        observations are droppedn and client sides of observations receive an
        errback.

        Requests that are not part of an exchange, eg. NON requests or requests
        that are waiting for their responses after an empty ACK are currently
        not handled."""

        self.token_interface.kill_transactions(remote, exception)

        for ((token, obs_remote), clientobservation) in list(self.outgoing_observations.items()):
            if remote != obs_remote:
                continue
            clientobservation().error(exception())

        for ((token, obs_remote), serverobservation) in list(self.incoming_observations.items()):
            if remote != obs_remote:
                continue
            ## FIXME this is not tested either
            serverobservation.deregister("Dropping due to kill_transactions")

    def next_token(self):
        """Reserve and return a new Token for request."""
        #TODO: add proper Token handling
        token = self.token
        self.token = (self.token + 1) & 0xffffffffffffffff
        return bytes.fromhex("%08x"%self.token)

    #
    # implement the tokenmanager interface
    #

    def dispatch_error(self, errno, remote):
        keys_for_removal = []
        for key, request in self.outgoing_requests.items():
            (token, request_remote) = key
            if request_remote == remote:
                request.add_exception(OSError(errno, os.strerror(errno)))
                keys_for_removal.append(key)
        for k in keys_for_removal:
            self.outgoing_requests.pop(key)

        # not cancelling incoming requests, as they have even less an API for
        # that than the outgoing ones; clearing the exchange monitors (in
        # message_manager) at least spares them retransmission hell, and apart
        # from that, they'll need to timeout by themselves.

    def process_request(self, request):
        key = tuple(request.opt.uri_path), request.remote

        if key in self.incoming_requests:
            self.log.debug("Delivering request to existing responder.")
            self.incoming_requests.pop(key).handle_next_request(request)
        else:
            responder = Responder(self, request)

    def process_response(self, response):
        key = (response.token, response.remote)
        if key not in self.outgoing_requests:
            # maybe it was a multicast...
            key = (response.token, None)

        try:
            request = self.outgoing_requests[key]
        except KeyError:
            return False

        # FIXME: there's a multicast aspect to that as well
        #
        # Is it necessary to look into .opt.observe here, wouldn't that better
        # be done by the higher-level code that knows about CoAP options?
        # Maybe, but at some point in TokenManager we *have* to look into the
        # options to see whether to expect a short- or long-running token.
        # Still, it would be an option not to send an is_last here and *always*
        # have the higher-level code indicate loss of interest in that exchange
        # when it detects that no more observations will follow.
        final = not (request.request.opt.observe == 0 and response.opt.observe is not None)

        if is_final:
            self.outgoing_requests.pop(key)

        request.add_response(response, is_last=final)
        return True

    #
    # implement RequestInterface
    #

    async def fill_or_recognize_remote(self, message):
        return await self.token_interface.fill_or_recognize_remote(message)

    def request(self, request):
        msg = request.request

        assert msg.code.is_request(), "Message code is not valid for request"

        # This might easily change, but right now, relying on the Context to
        # fill_remote early makes steps easier here.
        assert msg.remote is not None, "Remote not pre-populated"

        # FIXME: pick a suitably short one where available, and a longer one
        # for observations if many short ones are already in-flight
        msg.token = self.next_token()

        self.log.debug("Sending request - Token: %s, Remote: %s" % (msg.token.hex(), msg.remote))

        try:
            send_canceller = self.token_interface.send_message(msg)
        except Exception as e:
            request.add_exception(e)
            return

        if send_canceller is not None:
            # This needs to be called both when the requester cancels the
            # request, and when a response to the CON request comes in via a
            # different CON when the original ACK was lost, so the retransmits
            # can stop.
            #
            # FIXME: This might need a little sharper conditions: A fresh CON
            # should be sufficient to stop retransmits of a CON in a first
            # request, but when refreshing an observation, only an ACK tells us
            # that the updated observation got through. Also, multicast needs
            # to be an exception, but that generally needs handling here.
            #
            # It may be that it'd be wise to reduce the use of send_canceller
            # to situations when the request is actualy cancelled, and pass
            # some information to the token_interface about whether it should
            # keep an eye out for responses on that token and cancel
            # transmission accordingly.
            request.once_on_message(send_canceller)
            request.on_interest_end(send_canceller)

        key = (msg.token, msg.remote)
        self.outgoing_requests[key] = request
        request.on_interest_end(functools.partial(self.outgoing_requests.pop, key, None))

'''
    def multicast_request(self, request):
        return MulticastRequest(self, request).responses
'''


class PlumbingRequest:
    Event = namedtuple("Event", ("message", "exception", "is_last"))

    # called by the initiator of the request

    def __init__(self, request):
        self.request = request
        self._interest = asyncio.Future()
        self._events = asyncio.Queue()

        self._once_on_message = []
        self._on_interest_end = []
        # The default-argument closure makes sure no cyclic references are
        # formed here
        def handle_interest_end(future, *, interest_end=self._on_interest_end):
            while interest_end:
                interest_end.pop()()
        self._interest.add_done_callback(handle_interest_end)

    def stop_interest(self):
        self._interest.set_result(None)

    def poke(self):
        """Ask the responder for a life sign. It is up to the responder to
        ignore this (eg. because the responder is the library/application and
        can't be just gone), to issue a generic transport-dependent 'ping' to
        see whether the connection is still alive, or to retransmit the request
        if it is an observation over an unreliable channel.

        In any case, no status is reported directly to the poke, but if
        whatever the responder does fails, it will send an appropriate error
        message as a response."""
        raise NotImplementedError()

    # called by side

    def once_on_message(self, callback):
        self._once_on_message.append(callback)

    def on_interest_end(self, callback):
        self._on_interest_end.append(callback)

    # called by the responding side

    def add_response(self, response, is_last=False):
        self._events.put_nowait(self.Event(response, None, is_last))
        while self._once_on_message:
            self._once_on_message.pop()()

    def add_exception(self, exception, is_last=True):
        self._events.put_nowait(self.Event(None, exception, is_last))

    def revoke_responses(self, filterexpression):
        """Remove all pending responses from the response queue where
        filterexpression(msg) returns True. To be used primarily for filtering
        out old pending observation responses."""
        raise NotImplementedError()



'''
class Request(BaseUnicastRequest, interfaces.Request):
    """Class used to handle single outgoing request (without any blockwise handling)"""
    def cancel(self):
        # TODO cancel ongoing exchanges
        if self._requesttimeout:
            self._requesttimeout.cancel()
        self.response.cancel()

    def handle_final_response(self, response):
        if self.app_request.opt.uri_host:
            response.requested_hostinfo = hostportjoin(self.app_request.opt.uri_host, self.app_request.opt.uri_port)
        else:
            response.requested_hostinfo = self.app_request.unresolved_remote
        response.requested_path = self.app_request.opt.uri_path
        response.requested_query = self.app_request.opt.uri_query
        response.requested_scheme = self.app_request.requested_scheme

        self.response.set_result(response)

class MulticastRequest(BaseRequest):
    def __init__(self, protocol, request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.request = request

        if self.request.mtype != NON or self.request.code != GET or self.request.payload:
            raise ValueError("Multicast currently only supportet for NON GET")

        #: An asynchronous generator (``__aiter__`` / ``async for``) that
        #: yields responses until it is exhausted after a timeout
        self.responses = AsyncGenerator()

        asyncio.Task(self._init_phase2())

    async def _init_phase2(self):
        """See :meth:`Request._init_phase2`"""
        try:
            await self.protocol.fill_remote(self.request)

            await self._send_request(self.request)
        except Exception as e:
            self.responses.throw(e)

    async def _send_request(self, request):
        request.token = self.protocol.next_token()

        try:
            self.protocol.send_message(request)
        except Exception as e:
            self.responses.throw(e)
            return

        self.protocol.outgoing_requests[(request.token, None)] = self
        self.log.debug("Sending multicast request - Token: %s, Remote: %s" % (request.token.hex(), request.remote))

        self.protocol.loop.call_later(MULTICAST_REQUEST_TIMEOUT, self._timeout)

        for i in range(5):
            # FIXME that's not what the spec says. what does the spec say?
            await asyncio.sleep(i/2)
            self.protocol.send_message(request)

    def handle_response(self, response):
        # not setting requested_hostinfo, that needs to come from the remote
        response.requested_path = self.request.opt.uri_path
        response.requested_query = self.request.opt.get_option(OptionNumber.URI_QUERY) or ()

        # FIXME this should somehow backblock, but it's udp -- maybe rather limit queue length?
        self.responses.ayield(response)

    def _timeout(self):
        self.protocol.outgoing_requests.pop(self.request.token, None)
        self.responses.finish()
'''

class Responder:
    """Handler for an incoming request or (in blockwise) a group thereof

    Class includes methods that handle receiving incoming blockwise requests
    (only atomic operation on complete requests), searching for target
    resources, preparing responses and sending outgoing blockwise responses.

    To keep an eye on exchanges going on, a factory for ExchangeMonitor can be
    passed in that generates a monitor for every single message exchange
    created during the response."""

    # all mid handling here should move into the the MessageManager; it'll need
    # to look at the tokens and decide whether a message is eligible for
    # piggy-backing.
    #
    # send_empty_response is the responsibility of MessageManager (which needs
    # to keep track of unanswered incoming CONs)

    def __init__(self, protocol, request, exchange_monitor_factory=(lambda message: None)):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("responder")

        self.key = tuple(request.opt.uri_path), request.remote

        self.log.debug("New responder created, key %s"%(self.key,))

        # partial request while more block1 messages are incoming
        self._assembled_request = None
        self.app_response = None
        # that will be passed the single request. take care that this does not
        # linger -- either enqueue with incoming_requests (and a timeout), or
        # send a response which cancels the future.
        self.app_request = asyncio.Future()
        # used to track whether to reply with ACK or CON
        self._sent_empty_ack = False
        self._serverobservation = None

        self._exchange_monitor_factory = exchange_monitor_factory

        self._next_block_timeout = None

        asyncio.Task(self.dispatch_request(request))

    def handle_next_request(self, request):
        if self._next_block_timeout is not None: # that'd be the case only for the first time
            self._next_block_timeout.cancel()

        if self.app_request.done() == False:
            self.process_block1_in_request(request)
        else:
            self.process_block2_in_request(request)

    def process_block1_in_request(self, request):
        """Process an incoming request while in block1 phase.

        This method is responsible for finishing the app_request future
        and thus indicating that it should not be called any more, or
        scheduling itself again."""
        if request.opt.block1 is not None:
            block1 = request.opt.block1
            self.log.debug("Request with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))
            if block1.block_number == 0:
                #TODO: Check if resource is available - if not send error immediately
                #TODO: Check if method is allowed - if not send error immediately
                self.log.debug("New or restarted incoming blockwise request.")
                self._assembled_request = request
            else:
                if self._assembled_request is None:
                    self.respond_with_error(request, REQUEST_ENTITY_INCOMPLETE, "Beginning of block1 transaction unknown to server")
                    return

                try:
                    self._assembled_request._append_request_block(request)
                except error.NotImplemented:
                    self.respond_with_error(request, NOT_IMPLEMENTED, "Error: Request block received out of order!")
                    return
            if block1.more is True:
                #TODO: SUCCES_CODE Code should be either Changed or Created - Resource check needed
                #TODO: SIZE_CHECK1 should check if the size of incoming payload is still acceptable
                #TODO: SIZE_CHECK2 should check if Size option is present, and reject the resource if size too large

                self.log.debug("Sending block acknowledgement (allowing client to send next block).")

                self.send_non_final_response(request._generate_next_block1_response(), request)
            else:
                self.log.debug("Complete blockwise request received.")
                self.app_request.set_result(self._assembled_request)
        else:
            if self._assembled_request is not None:
                self.log.warning("Non-blockwise request received during blockwise transfer. Blockwise transfer cancelled, responding to single request.")
            self.app_request.set_result(request)

    async def dispatch_request(self, initial_block):
        """Dispatch incoming request - search context resource tree for
        resource in Uri Path and call proper CoAP Method on it."""

        if self.protocol.context.serversite is None:
            self.respond_with_error(initial_block, NOT_FOUND, "Context is not a server")
            return

        try:
            needs_blockwise = await self.protocol.context.serversite.needs_blockwise_assembly(initial_block)
        except Exception as e:
            self.respond_with_error(initial_block, INTERNAL_SERVER_ERROR, "")
            self.log.error("An exception occurred while requesting needs_blockwise: %r"%e, exc_info=e)
            return

        if needs_blockwise:
            self.handle_next_request(initial_block)

            try:
                request = await self.app_request
            except asyncio.CancelledError:
                # error has been handled somewhere else
                return
        else:
            request = initial_block

        delayed_ack = self.protocol.loop.call_later(EMPTY_ACK_DELAY, self.send_empty_ack, request)

        await self.handle_observe_request(request)

        try:
            response = await self.protocol.context.serversite.render(request)
        except error.RenderableError as e:
            self.respond_with_error(request, e.code, e.message)
        except Exception as e:
            self.respond_with_error(request, INTERNAL_SERVER_ERROR, "")
            self.log.error("An exception occurred while rendering a resource: %r"%e, exc_info=e)
        else:
            if response is NoResponse:
                self.send_final_response(response, request)
                return

            if response.code is None:
                response.code = CONTENT
            if not response.code.is_response():
                self.log.warning("Response does not carry response code (%r), application probably violates protocol."%response.code)

            self.handle_observe_response(request, response)

            if needs_blockwise:
                self.respond(response, request)
            else:
                self.send_final_response(response, request)
        finally:
            delayed_ack.cancel()

    def respond_with_error(self, request, code, payload):
        """Helper method to send error response to client."""
        payload = payload.encode('ascii')
        self.log.info("Sending error response: %r"%payload)
        response = Message(code=code, payload=payload)
        self.respond(response, request)

    def respond(self, app_response, request):
        """Take application-supplied response and prepare it for sending."""

        # if there was an error, make sure nobody hopes to get a result any more
        self.app_request.cancel()

        self.log.debug("Preparing response...")
        self.app_response = app_response

        self.process_block2_in_request(request)

    def process_block2_in_request(self, request):
        """Process incoming request with regard to Block2 option

        Method is recursive - calls itself until all response blocks are sent
        to client."""

        block2 = request.opt.block2
        if block2 is None:
            self.log.debug("Request without block option received into exting blockwise transfer, treating it as first block request.")
            block2 = BlockOption.BlockwiseTuple(0, 0, DEFAULT_BLOCK_SIZE_EXP)
        else:
            self.log.debug("Request with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))

        # the application may guide the choice of block sizes
        if self.app_response.opt.block2:
            block2 = block2.reduced_to(self.app_response.opt.block2.size_exponent)
        else:
            block2 = block2.reduced_to(DEFAULT_BLOCK_SIZE_EXP)

        if block2.start == 0 and block2.size >= len(self.app_response.payload):
            self.send_final_response(self.app_response, request)
            return

        next_block = self.app_response._extract_block(block2.block_number, block2.size_exponent)
        if next_block is None:
            # TODO is this the right error code here?
            self.send_final_response(Message(code=REQUEST_ENTITY_INCOMPLETE, payload=b"Request out of range"), request)
            return
        if next_block.opt.block2.more is True:
            self.app_response.opt.block2 = next_block.opt.block2
            self.send_non_final_response(next_block, request)
        else:
            self.send_final_response(next_block, request)

    def send_non_final_response(self, response, request):
        """Helper method to send a response to client, and setup a timeout for
        client. This also registers the responder with the protocol again to
        receive the next message."""

        self.log.debug("Keeping the app_response around for some more time")
        key = tuple(request.opt.uri_path), request.remote

        def timeout_non_final_response(self):
            self.log.info("Waiting for next blockwise request timed out")
            self.protocol.incoming_requests.pop(self.key)
            self.app_request.cancel()

        # we don't want to have this incoming request around forever
        self._next_block_timeout = self.protocol.loop.call_later(MAX_TRANSMIT_WAIT, timeout_non_final_response, self)
        self.protocol.incoming_requests[self.key] = self

        self.send_response(response, request)

    def send_final_response(self, response, request):
        # no need to unregister anything; the incoming_requests registrations
        # only live from one request to the next anyway
        self.send_response(response, request)

        # break reference. TODO: this helps the protocol free itself, but not
        # the responder, which seems to be kept alive by lingering timeout
        # handlers.
        self.protocol = None

    def send_response(self, response, request):
        """Send a response or single response block.

           This method is used in 4 situations:
           - sending success non-blockwise response
           - asking client to send blockwise (Block1) request block
           - sending blockwise (Block2) response block
           - sending any error response
        """

        if response is NoResponse:
            self.log.debug("Sending NoResponse")
            if request.mtype is CON and not self._sent_empty_ack:
                self.send_empty_ack(request, "gave NoResponse")
            return

        response.token = request.token
        self.log.debug("Sending token: %s", response.token.hex())
        response.remote = request.remote
        if request.opt.block1 is not None:
            response.opt.block1 = request.opt.block1
            # response.opt.block1.more does not need to be touched as we'll
            # always send "more" if the client has "more" to say
        if response.mtype is None:
            if self._sent_empty_ack:
                response.mtype = CON
                self._sent_empty_ack = False
            else:
                response.mtype = ACK
        if response.mid is None and response.mtype in (ACK, RST):
                response.mid = request.mid
        self.log.debug("Sending response, type = %s (request type = %s)" % (response.mtype, request.mtype))
        self.protocol.send_message(response, self._exchange_monitor_factory(request))

    def send_empty_ack(self, request, _reason="takes too long"):
        """Send separate empty ACK when response preparation takes too long.

        Currently, this can happen only once per Responder, that is, when the
        last block1 has been transferred and the first block2 is not ready
        yet."""

        self.log.debug("Response preparation %s - sending empty ACK."%_reason)
        ack = Message(mtype=ACK, code=EMPTY, payload=b"")
        # not going via send_response because it's all only about the message id
        ack.remote = request.remote
        ack.mid = request.mid
        self.protocol.send_message(ack)
        self._sent_empty_ack = True

    async def handle_observe_request(self, request):
        key = ServerObservation.request_key(request)

        if key in self.protocol.incoming_observations:
            old_observation = self.protocol.incoming_observations[key]
            # there's no real need to distinguish real confirmations and
            # pseudorequests so far (as the pseudo requests will always have
            # their observe option set to 0), but it's good reading in the logs
            # and might be required in case someone wants to keep an eye on
            # renewed intesrest that is allowed since ietf-10.
            if request.mtype is not None:
                self.log.info("This is a real request belonging to an active observation")
                if request.opt.observe != 0:
                    # either it's 1 (deregister) or someone is trying to
                    # deregister by not sending an observe option at all
                    old_observation.deregister("Client requested termination" if request.opt.observe == 1 else "Unexpected observe value: %r"%(request.opt.observe,))
                    return
            else:
                self.log.info("This is a pseudo-request")
            self._serverobservation = old_observation
            return

        if request.code in (GET, FETCH) and request.opt.observe == 0 and hasattr(self.protocol.context.serversite, "add_observation"):
            sobs = ServerObservation(self.protocol, request, self.log)
            await self.protocol.context.serversite.add_observation(request, sobs)
            if sobs.accepted:
                self._serverobservation = sobs
            else:
                sobs.deregister("Resource does not provide observation")

    def handle_observe_response(self, request, response):
        """Modify the response according to the Responder's understanding of
        the involved observation (eg. drop the observe flag it's not involved
        in an observation or the observation was cancelled), and update the
        Responder/context if the response modifies the observation state (eg.
        by being unsuccessful)."""
        if request.mtype is None:
            # this is the indicator that the request was just injected
            response.mtype = CON

        if self._serverobservation is None or self._serverobservation.cancelled:
            if response.opt.observe is not None:
                self.log.info("Dropping observe option from response (no server observation was created for this request)")
            response.opt.observe = None
            return

        # FIXME this is in parts duplicated in ServerObservation.trigger, and
        # thus should be moved somewhere else

        if response.code not in (VALID, CONTENT):
            self._serverobservation.deregister("No successful response code")
            return

        self.log.debug("Acknowledging observation to client.")

        response.opt.observe = self._serverobservation.observe_index

class ServerObservation(object):
    """An active CoAP observation inside a server is described as a
    ServerObservation object.

    It keeps a complete copy of the original request for simplicity (while it
    actually would only need parts of that request, like the accept option).

    A ServerObservation has two boolean states: accepted and cancelled. It is
    originally neither, gets accepted when a
    :meth:`.ObservableResource.add_observation` method does :meth:`.accept()` it,
    and gets cancelled by incoming packages of the same identifier, RST/timeout
    on notifications or the observed resource. Beware that an accept can happen
    after cancellation if the client changes his mind quickly, but the resource
    takes time to decide whether it can be observed.
    """

    def __init__(self, original_protocol, original_request, requester_log):
        self.original_protocol = original_protocol
        self.original_request = original_request
        self.log = requester_log.getChild("observation")
        self.observe_index = 0
        self.cancelled = False
        self.accepted = False

        self.original_protocol.incoming_observations[self.identifier] = self

        self.log.debug("Observation created: %r"%self)

    def accept(self, cancellation_callback):
        assert not self.accepted
        self.accepted = True
        if self.cancelled:
            # poor resource is just establishing that it can observe. let's
            # give it the time to finish add_observation and not worry about a
            # few milliseconds. (after all, this is a rare condition and people
            # will not test for it).
            self.original_protocol.loop.call_soon(cancellation_callback)
        else:
            self.resource_cancellation_callback = cancellation_callback

    def deregister(self, reason):
        self.log.debug("Taking down observation: %s", reason)
        self._cancel()

    def _cancel(self):
        assert not self.cancelled
        self.cancelled = True

        if self.accepted:
            self.resource_cancellation_callback()
            del self.resource_cancellation_callback

        popped = self.original_protocol.incoming_observations.pop(self.identifier)
        assert popped is self

    identifier = property(lambda self: self.request_key(self.original_request))

    @staticmethod
    def request_key(request):
        return (request.remote, request.token)

    def _create_new_request(self):
        # TODO this indicates that the request is injected -- overloading .mtype is not the cleanest thing to do hee
        # further TODO this should be a copy once we decide that request receivers may manipulate them
        self.original_request.mtype = None
        self.original_request.mid = None

        return self.original_request

    def trigger(self, response=None):
        # this implements the second implementation suggestion from
        # draft-ietf-coap-observe-11 section 4.4
        #
        ## @TODO handle situations in which this gets called more often than
        #        2^32 times in 256 seconds (or document why we can be sure that
        #        that will not happen)
        self.observe_index = (self.observe_index + 1) % (2**24)

        request = self._create_new_request()
        if response is None:
            self.log.debug("Server observation triggered, injecting original request %r again"%request)

            # bypassing parsing and duplicate detection, pretend the request came in again
            #
            # the prediction is that the factory will be called exactly once, as no
            # blockwise is involved
            Responder(self.original_protocol, request, lambda message: self.ObservationExchangeMonitor(self))
        else:
            self.log.debug("Server observation triggered, responding with application provided answer")

            if response.opt.block2 != None and not (response.opt.block2.more == False and response.opt.block2.block_number == 0):
                self.log.warning("Observation trigger with immediate response contained nontrivial block option, failing the observation.")
                response = Message(code=INTERNAL_SERVER_ERROR, payload=b"Observation answer contains strange block option")

            response.mid = None

            # FIXME this is duplicated in parts from Response.send_response

            response.token = request.token
            response.remote = request.remote

            if response.mtype is None or response.opt.observe is None:
                # not sure under which conditions this should actually happen
                response.mtype = CON

            # FIXME this is duplicated in parts from handle_observe_response

            if response.code not in (VALID, CONTENT):
                self.log.debug("Trigger response produced no valid response code, tearing down observation.")
                self._cancel()
            else:
                response.opt.observe = self.observe_index

            self.original_protocol.send_message(response, self.ObservationExchangeMonitor(self))
