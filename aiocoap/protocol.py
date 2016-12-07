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


import os
import random
import struct
import binascii
import functools
import socket
import asyncio
import weakref

from .util.queuewithend import QueueWithEnd
from .util.asyncio import cancel_thoroughly
from .util import hostportjoin
from . import error

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

from . import error
from . import interfaces
from .numbers import *
from .message import Message

class Context(asyncio.DatagramProtocol, interfaces.RequestProvider):
    """An object that passes messages between an application and the network

    A :class:`.Context` gets bound to a network interface as an asyncio
    protocol. It manages the basic CoAP network mechanisms like message
    deduplication and retransmissions, and delegates management of blockwise
    transfer as well as the details of matching requests with responses to the
    :class:`Request` and :class:`Responder` classes.

    In that respect, a Context (as currently implemented) is also an endpoint.
    It is anticipated, though, that issues arise due to which the
    implementation won't get away with creating a single socket, and that it
    will be required to deal with multiple endpoints. (E.g. the V6ONLY=0 option
    is not portable to some OS, and implementations might need to bind to
    different ports on different interfaces in multicast contexts). When those
    distinctions will be implemented, message dispatch will stay with the
    context, which will then deal with the individual endpoints.

    In a way, a :class:`.Context` is the single object all CoAP messages that
    get treated by a single application pass by.

    Context creation
    ----------------

    Instead of passing a protocol factory to the asyncio loop's
    create_datagram_endpoint method, the following convenience functions are
    recommended for creating a context:

    .. automethod:: create_client_context
    .. automethod:: create_server_context

    If you choose to create the context manually, make sure to wait for its
    :attr:`ready` future to complete, as only then can messages be sent.

    Dispatching messages
    --------------------

    A context's public API consists of the :meth:`send_message` function,
    the :attr:`outgoing_requests`, :attr:`incoming_requests` and
    :attr:`outgoing_obvservations` dictionaries, and the :attr:`serversite`
    object, but those are not stabilized yet, and for most applications the
    following convenience functions are more suitable:

    .. automethod:: request

    .. automethod:: multicast_request

    If more control is needed, eg. with observations, create a
    :class:`Request` yourself and pass the context to it.
    """

    def __init__(self, loop=None, serversite=None, loggername="coap"):
        self.message_id = random.randint(0, 65535)
        self.token = random.randint(0, 65535)
        self.serversite = serversite
        self._recent_messages = {}  #: recently received messages (remote, message-id): None or result-message
        self._active_exchanges = {}  #: active exchanges i.e. sent CON messages (remote, message-id): (exchange monitor, cancellable timeout)
        self._backlogs = {} #: per-remote list of (backlogged package, exchange-monitor) tupless (keys exist iff there is an active_exchange with that node)
        self.outgoing_requests = {}  #: Unfinished outgoing requests (identified by token and remote)
        self.incoming_requests = {}  #: Unfinished incoming requests. ``(path-tuple, remote): Request``
        self.outgoing_observations = {} #: Observations where this context acts as client. ``(token, remote) -> weak(ClientObservation)``
        self.incoming_observations = {} #: Observation where this context acts as server. ``(token, remote) -> ServerObservation``. This is managed by :cls:ServerObservation and :meth:`.Responder.handle_observe_request`.

        self.log = logging.getLogger(loggername)

        self.loop = loop or asyncio.get_event_loop()

        self.transport_endpoints = []

    @asyncio.coroutine
    def shutdown(self):
        """Take down the listening socket and stop all related timers.

        After this coroutine terminates, and once all external references to
        the object are dropped, it should be garbage-collectable."""

        self.log.debug("Shutting down context")
        for exchange_monitor, cancellable in self._active_exchanges.values():
            if exchange_monitor is not None:
                exchange_monitor.cancelled()
            cancellable.cancel()
        for observation in list(self.incoming_observations.values()):
            observation.deregister("Server going down")
        self._active_exchanges = None

        yield from asyncio.wait([te.shutdown() for te in self.transport_endpoints], timeout=3, loop=self.loop)

    # pause_writing and resume_writing are not implemented, as the protocol
    # should take care of not flooding the output itself anyway (NSTART etc).

    #
    # coap dispatch
    #

    def _dispatch_message(self, message):
        """Feed a message through the message-id, message-type and message-code
        sublayers of CoAP"""

        self.log.debug("Incoming message %r" % message)
        if self._deduplicate_message(message) is True:
            return

        if message.mtype in (ACK, RST):
            self._remove_exchange(message)

        if message.code is EMPTY and message.mtype is CON:
            self._process_ping(message)
        elif message.code is EMPTY and message.mtype in (ACK, RST):
            pass # empty ack has already been handled above
        elif message.code.is_request() and message.mtype in (CON, NON):
            # the request handler will have to deal with sending ACK itself, as
            # it might be timeout-related
            self._process_request(message)
        elif message.code.is_response() and message.mtype in (CON, NON, ACK):
            success = self._process_response(message)
            if success:
                if message.mtype is CON:
                    #TODO: Some variation of send_empty_ack should be used
                    ack = Message(mtype=ACK, mid=message.mid, code=EMPTY, payload=b"")
                    ack.remote = message.remote
                    self.send_message(ack)
            else:
                self.log.info("Response not recognized - sending RST.")
                rst = Message(mtype=RST, mid=message.mid, code=EMPTY, payload='')
                rst.remote = message.remote
                self.send_message(rst)
        else:
            self.log.warning("Received a message with code %s and type %s (those don't fit) from %s, ignoring it."%(message.code, message.mtype, message.remote))

    def _dispatch_error(self, errno, remote):
        self.log.debug("Incoming error %d from %r", errno, remote)

        # cancel requests first, and then exchanges: cancelling the pending
        # exchange would trigger enqueued requests to be transmitted

        keys_for_removal = []
        for key, request in self.outgoing_requests.items():
            (token, request_remote) = key
            if request_remote == remote:
                request.response.set_exception(OSError(errno, os.strerror(errno)))
            keys_for_removal.append(key)
        for k in keys_for_removal:
            self.outgoing_requests.pop(key)

        # not cancelling incoming requests, as they have even less an API for
        # that than the outgoing ones; clearing the exchange monitors at least
        # spares them retransmission hell, and apart from that, they'll need to
        # timeout by themselves.

        keys_for_removal = []
        for key, (monitor, cancellable_timeout) in self._active_exchanges.items():
            (exchange_remote, message_id) = key
            if remote == exchange_remote:
                if monitor is not None:
                    monitor.rst() # FIXME: add API for better errors
                cancel_thoroughly(cancellable_timeout)
                keys_for_removal.append(key)
        for k in keys_for_removal:
            self._active_exchanges.pop(k)

    #
    # coap dispatch, message-id sublayer: duplicate handling
    #

    def _deduplicate_message(self, message):
        """Return True if a message is a duplicate, and re-send the stored
        response if available.

        Duplicate is a message with the same Message ID (mid) and sender
        (remote), as message received within last EXCHANGE_LIFETIME seconds
        (usually 247 seconds)."""

        key = (message.remote, message.mid)
        if key in self._recent_messages:
            if message.mtype is CON:
                if self._recent_messages[key] is not None:
                    self.log.info('Duplicate CON received, sending old response again')
                    self.send_message(self._recent_messages[key])
                else:
                    self.log.info('Duplicate CON received, no response to send yet')
            else:
                self.log.info('Duplicate NON, ACK or RST received')
            return True
        else:
            self.log.debug('New unique message received')
            self.loop.call_later(EXCHANGE_LIFETIME, functools.partial(self._recent_messages.pop, key))
            self._recent_messages[key] = None
            return False

    def _store_response_for_duplicates(self, message):
        """If the message is the response can be used to satisfy a future
        duplicate message, store it."""

        key = (message.remote, message.mid)
        if key in self._recent_messages:
            self._recent_messages[key] = message

    #
    # coap dispatch, message-type sublayer: retransmission handling
    #

    def _add_exchange(self, message, exchange_monitor=None):
        """Add an "exchange" for outgoing CON message.

        CON (Confirmable) messages are automatically retransmitted by protocol
        until ACK or RST message with the same Message ID is received from
        target host."""

        key = (message.remote, message.mid)

        if message.remote not in self._backlogs:
            self._backlogs[message.remote] = []

        timeout = random.uniform(ACK_TIMEOUT, ACK_TIMEOUT * ACK_RANDOM_FACTOR)

        next_retransmission = self._schedule_retransmit(message, timeout, 0)
        self._active_exchanges[key] = (exchange_monitor, next_retransmission)

        self.log.debug("Exchange added, message ID: %d." % message.mid)

    def _remove_exchange(self, message):
        """Remove exchange from active exchanges and cancel the timeout to next
        retransmission."""
        key = (message.remote, message.mid)

        if key not in self._active_exchanges:
            self.log.warn("Received %s from %s, but could not match it to a running exchange."%(message.mtype, message.remote))
            return

        exchange_monitor, next_retransmission = self._active_exchanges.pop(key)
        cancel_thoroughly(next_retransmission)
        if exchange_monitor is not None:
            if message.mtype is RST:
                exchange_monitor.rst()
            else:
                exchange_monitor.response(message)
        self.log.debug("Exchange removed, message ID: %d." % message.mid)

        self._continue_backlog(message.remote)

    def _continue_backlog(self, remote):
        """After an exchange has been removed, start working off the backlog or
        clear it completely."""

        if remote not in self._backlogs:
            # if active exchanges were something we could do a
            # .register_finally() on, we could chain them like that; if we
            # implemented anything but NSTART=1, we'll need a more elaborate
            # system anyway
            raise AssertionError("backlogs/active_exchange relation violated (implementation error)")

        # first iteration is sure to happen, others happen only if the enqueued
        # messages were NONs
        while not any(r == remote for r, mid in self._active_exchanges.keys()):
            if self._backlogs[remote] != []:
                next_message, exchange_monitor = self._backlogs[remote].pop(0)
                self._send_initially(next_message, exchange_monitor)
            else:
                del self._backlogs[remote]
                break

    def _schedule_retransmit(self, message, timeout, retransmission_counter):
        """Create and return a call_later for first or subsequent
        retransmissions."""

        # while this could just as well be done in a lambda or with the
        # arguments passed to call_later, in this form makes the test cases
        # easier to debug (it's about finding where references to a Context
        # are kept around; contexts should be able to shut down in an orderly
        # way without littering references in the loop)

        def retr(self=self,
                message=message,
                timeout=timeout,
                retransmission_counter=retransmission_counter,
                doc="If you read this, have a look at _schedule_retransmit",
                id=object()):
            self._retransmit(message, timeout, retransmission_counter)
        return self.loop.call_later(timeout, retr)

    def _retransmit(self, message, timeout, retransmission_counter):
        """Retransmit CON message that has not been ACKed or RSTed."""
        key = (message.remote, message.mid)

        exchange_monitor, next_retransmission = self._active_exchanges.pop(key)
        # this should be a no-op, but let's be sure
        cancel_thoroughly(next_retransmission)

        if retransmission_counter < MAX_RETRANSMIT:
            self.log.info("Retransmission, Message ID: %d." % message.mid)
            self._send_via_transport(message)
            retransmission_counter += 1
            timeout *= 2

            next_retransmission = self._schedule_retransmit(message, timeout, retransmission_counter)
            self._active_exchanges[key] = (exchange_monitor, next_retransmission)
            if exchange_monitor is not None:
                exchange_monitor.retransmitted()
        else:
            self.log.info("Exchange timed out")
            if exchange_monitor is not None:
                exchange_monitor.timeout()
            self._continue_backlog(message.remote)

    #
    # coap dispatch, message-code sublayer: triggering custom actions based on incoming messages
    #

    def _process_ping(self, message):
        self.log.info('Received CoAP Ping from %s, replying with RST.'%(message.remote,))
        rst = Message(mtype=RST, mid=message.mid, code=EMPTY, payload=b'')
        rst.remote = message.remote
        self.send_message(rst)

    def _process_request(self, request):
        """Spawn a Responder for an incoming request, or feed a long-running
        responder if one exists."""

        key = tuple(request.opt.uri_path), request.remote

        if key in self.incoming_requests:
            self.log.debug("Delivering request to existing responder.")
            self.incoming_requests.pop(key).handle_next_request(request)
        else:
            responder = Responder(self, request)

    def _process_response(self, response):
        """Feed a response back to whatever might expect it.

        Returns True if the response was expected (and should be ACK'd
        depending on mtype), ans False if it was not expected (and should be
        RST'd)."""

        self.log.debug("Received Response: %r" % response)

        request = self.outgoing_requests.pop((response.token, response.remote), None)
        if request is not None:
            request.handle_response(response)
            return True

        request = self.outgoing_requests.get((response.token, None), None)
        if request is not None:
            # that's exactly the `MulticastRequest`s so far
            request.handle_response(response)
            return True

        obsref = self.outgoing_observations.get((response.token, response.remote), None)
        if obsref is not None:
            observation = obsref()
            ## @TODO: deduplication based on observe option value, collecting
            # the rest of the resource if blockwise
            observation.callback(response)

            if response.opt.observe is None:
                observation.error(error.ObservationCancelled())

            return True

        return False

    #
    # outgoing messages
    #

    @asyncio.coroutine
    def fill_remote(self, message):
      te, = self.transport_endpoints
      yield from te.fill_remote(message)

    def send_message(self, message, exchange_monitor=None):
        """Encode and send message. This takes care of retransmissions (if
        CON), message IDs and rate limiting, but does not hook any events to
        responses. (Use the :class:`Request` class or responding resources
        instead; those are the typical callers of this function.)

        If notification about the progress of the exchange is required, an
        ExchangeMonitor can be passed in, which will receive the appropriate
        callbacks."""

        if message.mtype == CON and message.remote.is_multicast:
            raise ValueError("Refusing to send CON message to multicast address")

        if message.mid is None:
            message.mid = self._next_message_id()

        if message.mtype == CON and message.remote in self._backlogs:
            self.log.debug("Message to %s put into backlog"%(message.remote,))
            if exchange_monitor is not None:
                exchange_monitor.enqueued()
            self._backlogs[message.remote].append((message, exchange_monitor))
        else:
            self._send_initially(message, exchange_monitor)

    def _send_initially(self, message, exchange_monitor=None):
        """Put the message on the wire for the first time, starting retransmission timeouts"""

        self.log.debug("Sending message %r" % message)

        if message.mtype is CON:
            self._add_exchange(message, exchange_monitor)

        if exchange_monitor is not None:
            exchange_monitor.sent()

        self._store_response_for_duplicates(message)

        self._send_via_transport(message)

    def _send_via_transport(self, message):
        """Put the message on the wire"""

        te, = self.transport_endpoints
        te.send(message)

    def _next_message_id(self):
        """Reserve and return a new message ID."""
        message_id = self.message_id
        self.message_id = 0xFFFF & (1 + self.message_id)
        return message_id

    def next_token(self):
        """Reserve and return a new Token for request."""
        #TODO: add proper Token handling
        token = self.token
        self.token = (self.token + 1) & 0xffffffffffffffff
        return binascii.a2b_hex("%08x"%self.token)

    #
    # request interfaces
    #

    def request(self, request, **kwargs):
        """TODO: create a proper interface to implement and deprecate direct instanciation again"""
        return Request(self, request, **kwargs)

    def multicast_request(self, request):
        return MulticastRequest(self, request).responses

    #
    # convenience methods for class instanciation
    #

    @classmethod
    @asyncio.coroutine
    def create_client_context(cls, *, dump_to=None, loggername="coap", loop=None):
        """Create a context bound to all addresses on a random listening port.

        This is the easiest way to get an context suitable for sending client
        requests.
        """

        if loop is None:
            loop = asyncio.get_event_loop()

        self = cls(loop=loop, serversite=None, loggername=loggername)

        from .transports.udp6 import TransportEndpointUDP6

        self.transport_endpoints.append((yield from TransportEndpointUDP6.create_client_transport_endpoint(new_message_callback=self._dispatch_message, new_error_callback=self._dispatch_error, log=self.log, loop=loop, dump_to=dump_to)))

        return self

    @classmethod
    @asyncio.coroutine
    def create_server_context(cls, site, bind=("::", COAP_PORT), *, dump_to=None, loggername="coap-server", loop=None):
        """Create an context, bound to all addresses on the CoAP port (unless
        otherwise specified in the ``bind`` argument).

        This is the easiest way to get a context suitable both for sending
        client and accepting server requests."""

        if loop is None:
            loop = asyncio.get_event_loop()

        self = cls(loop=loop, serversite=site, loggername=loggername)

        from .transports.udp6 import TransportEndpointUDP6

        self.transport_endpoints.append((yield from TransportEndpointUDP6.create_server_transport_endpoint(new_message_callback=self._dispatch_message, new_error_callback=self._dispatch_error, log=self.log, loop=loop, dump_to=dump_to, bind=bind)))

        return self

    def kill_transactions(self, remote, exception=error.CommunicationKilled):
        """Abort all pending exchanges and observations to a given remote.

        The exact semantics of this are not yet completely frozen -- currently,
        pending exchanges are treated as if they timeouted, server sides of
        observations are droppedn and client sides of observations receive an
        errback.

        Requests that are not part of an exchange, eg. NON requests or requests
        that are waiting for their responses after an empty ACK are currently
        not handled."""

        for ((exchange_remote, messageid), (exchangemonitor, cancellabletimeout)) in self._active_exchanges.items():
            if remote != exchange_remote:
                continue

            ## FIXME: this should receive testing, but a test setup would need
            # precise timing to trigger this code path
            ## FIXME: this does not actually abort the request, as the protocol
            # does not have a way to tell a request that it won't complete. so
            # actually, the request will just need to time out. (typical
            # requests don't use an exchange monitor).
            cancellabletimeout.cancel()
            if exchangemonitor is not None:
                exchangemonitor.rst()
            self._active_exchanges.pop((exchange_remote, messageid))

        for ((token, obs_remote), clientobservation) in list(self.outgoing_observations.items()):
            if remote != obs_remote:
                continue
            clientobservation().error(exception())

        for ((token, obs_remote), serverobservation) in list(self.incoming_observations.items()):
            if remote != obs_remote:
                continue
            ## FIXME this is not tested either
            serverobservation.deregister("Dropping due to kill_transactions")

class BaseRequest(object):
    """Common mechanisms of :class:`Request` and :class:`MulticastRequest`"""

class Request(BaseRequest, interfaces.Request):
    """Class used to handle single outgoing request.

    Class includes methods that handle sending outgoing blockwise requests and
    receiving incoming blockwise responses."""

    def __init__(self, protocol, app_request, exchange_monitor_factory=(lambda message: None), handle_blockwise=True):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.app_request = app_request
        self._assembled_response = None
        self.handle_blockwise = handle_blockwise

        self._exchange_monitor_factory = exchange_monitor_factory

        self._request_transmitted_completely = False

        self._requesttimeout = None

        if self.app_request.code.is_request() is False:
            raise ValueError("Message code is not valid for request")

        self.response = asyncio.Future()
        self.response.add_done_callback(self._response_cancellation_handler)

        if self.app_request.opt.observe is not None:
            self.observation = ClientObservation(self.app_request)
            self._observation_handled = False

        asyncio.Task(self._init_phase2())

    @asyncio.coroutine
    def _init_phase2(self):
        """Later aspects of initialization that deal more with sending the
        message than with the setup of the requester

        Those are split off into a dedicated function because completion might
        depend on async results."""

        try:
            yield from self.protocol.fill_remote(self.app_request)

            size_exp = DEFAULT_BLOCK_SIZE_EXP
            if self.app_request.opt.block1 is not None and self.handle_blockwise:
                assert self.app_request.opt.block1.block_number == 0, "Unexpected block number in app_request"
                size_exp = self.app_request.opt.block1.size_exponent
            if len(self.app_request.payload) > (2 ** (size_exp + 4)) and self.handle_blockwise:
                request = self.app_request._extract_block(0, size_exp)
                self.app_request.opt.block1 = request.opt.block1
            else:
                request = self.app_request
                self._request_transmitted_completely = True

            self.send_request(request)
        except Exception as e:
            self._set_response_and_observation_error(e)

    def _set_response_and_observation_error(self, e):
        self.response.set_exception(e)
        if self.app_request.opt.observe is not None:
            self._observation_handled = True
            self.observation.error(e)

    def cancel(self):
        # TODO cancel ongoing exchanges
        if self._requesttimeout:
            cancel_thoroughly(self._requesttimeout)
        self.response.cancel()

    def _response_cancellation_handler(self, response_future):
        if self._requesttimeout:
            cancel_thoroughly(self._requesttimeout)
        if self.response.cancelled():
            self.cancel()

    def send_request(self, request):
        """Send a request or single request block.

           This method is used in 3 situations:
           - sending non-blockwise request
           - sending blockwise (Block1) request block
           - asking server to send blockwise (Block2) response block
        """

        def timeout_request(self=self):
            """Clean the Request after a timeout."""

            self.log.info("Request timed out")
            del self.protocol.outgoing_requests[(request.token, request.remote)]
            self._set_response_and_observation_error(error.RequestTimedOut())

        if request.mtype is None:
            request.mtype = CON
        request.token = self.protocol.next_token()

        try:
            self.protocol.send_message(request, self._exchange_monitor_factory(request))
        except Exception as e:
            self._set_response_and_observation_error(e)
        else:
            if self._requesttimeout:
                cancel_thoroughly(self._requesttimeout)
            self.log.debug("Timeout is %r"%REQUEST_TIMEOUT)
            self._requesttimeout = self.protocol.loop.call_later(REQUEST_TIMEOUT, timeout_request)
            self.protocol.outgoing_requests[(request.token, request.remote)] = self

            self.log.debug("Sending request - Token: %s, Remote: %s" % (binascii.b2a_hex(request.token).decode('ascii'), request.remote))

    def handle_response(self, response):
        if not self._request_transmitted_completely:
            self.process_block1_in_response(response)
        else:
            self.process_block2_in_response(response)

    def process_block1_in_response(self, response):
        """Process incoming response with regard to Block1 option."""

        if response.opt.block1 is None:
            # it's not up to us here to 
            if response.code.is_successful(): # an error like "unsupported option" would be ok to return, but success?
                self.log.warning("Block1 option completely ignored by server, assuming it knows what it is doing.")
            self.process_block2_in_response(response)
            return

        block1 = response.opt.block1
        self.log.debug("Response with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))

        if block1.block_number != self.app_request.opt.block1.block_number:
            self._set_response_and_observation_error(UnexpectedBlock1Option())

        if block1.size_exponent < self.app_request.opt.block1.size_exponent:
            next_number = (self.app_request.opt.block1.block_number + 1) * 2 ** (self.app_request.opt.block1.size_exponent - block1.size_exponent)
            next_block = self.app_request._extract_block(next_number, block1.size_exponent)
        else:
            next_block = self.app_request._extract_block(self.app_request.opt.block1.block_number + 1, block1.size_exponent)

        if next_block is not None:
            self.app_request.opt.block1 = next_block.opt.block1

            # TODO: ignoring block1.more so far -- if it is False, we might use
            # the information about what has been done so far.

            self.send_request(next_block)
        else:
            if block1.more is False:
                self._request_transmitted_completely = True
                self.process_block2_in_response(response)
            else:
                self._set_response_and_observation_error(UnexpectedBlock1Option())

    def process_block2_in_response(self, response):
        """Process incoming response with regard to Block2 option."""

        if self.response.done():
            self.log.info("Disregarding incoming message as response Future is done (probably cancelled)")
            return

        if self.app_request.opt.observe is not None and self._assembled_response == None:
            # assembled response indicates it's the first response package
            self.register_observation(response)

        if response.opt.block2 is not None and self.handle_blockwise:
            block2 = response.opt.block2
            self.log.debug("Response with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            if self._assembled_response is not None:
                try:
                    self._assembled_response._append_response_block(response)
                except error.Error as e:
                    self.log.error("Error assembling blockwise response, passing on error %r"%e)
                    self.response.set_exception(e)
                    return
            else:
                if block2.block_number == 0:
                    self.log.debug("Receiving blockwise response")
                    self._assembled_response = response
                else:
                    self.log.error("Error assembling blockwise response (expected first block)")
                    self.response.set_exception(UnexpectedBlock2())
                    return
            if block2.more is True:
                self.send_request(self.app_request._generate_next_block2_request(response))
            else:
                self.handle_final_response(self._assembled_response)
        else:
            if self._assembled_response is not None:
                self.log.warning("Server sent non-blockwise response after having started a blockwise transfer. Blockwise transfer cancelled, accepting single response.")
            self.handle_final_response(response)

    def handle_final_response(self, response):
        if self.app_request.opt.uri_host:
            response.requested_hostinfo = hostportjoin(self.app_request.opt.uri_host, self.app_request.opt.uri_port)
        else:
            response.requested_hostinfo = self.app_request.unresolved_remote
        response.requested_path = self.app_request.opt.uri_path
        response.requested_query = self.app_request.opt.uri_query

        self.response.set_result(response)

    def register_observation(self, response):
        assert self._observation_handled == False
        self._observation_handled = True

        if not response.code.is_successful() or response.opt.observe is None:
            if not self.observation.cancelled:
                self.observation.error(error.NotObservable())
        else:
            self.observation._register(self.protocol.outgoing_observations, (response.token, response.remote))

    ### Alternatives to waiting for .response

    @property
    @asyncio.coroutine
    def response_raising(self):
        """An awaitable that returns if a response comes in and is successful,
        otherwise raises generic network exception or a
        :class:`.error.ResponseWrappingError` for unsuccessful responses.

        Experimental Interface."""

        response = yield from self.response
        if not response.code.is_successful():
            raise error.ResponseWrappingError(response)

        return response

    @property
    @asyncio.coroutine
    def response_nonraising(self):
        """An awaitable that rather returns a 500ish fabricated message (as a
        proxy would return) instead of raising an exception.

        Experimental Interface."""

        try:
            return (yield from self.response)
        except error.RenderableError:
            return e.to_message()
        except Exception as e:
            return Message(code=INTERNAL_SERVER_ERROR)

class MulticastRequest(BaseRequest):
    def __init__(self, protocol, request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.request = request

        if self.request.mtype != NON or self.request.code != GET or self.request.payload:
            raise ValueError("Multicast currently only supportet for NON GET")

        self.responses = QueueWithEnd()

        asyncio.Task(self._init_phase2())

    @asyncio.coroutine
    def _init_phase2(self):
        """See :meth:`Request._init_phase2`"""
        try:
            yield from self.protocol.fill_remote(self.request)

            yield from self._send_request(self.request)
        except Exception as e:
            self.responses.put_exception(e)

    def _send_request(self, request):
        request.token = self.protocol.next_token()

        try:
            self.protocol.send_message(request)
        except Exception as e:
            self.responses.put_exception(e)
            return

        self.protocol.outgoing_requests[(request.token, None)] = self
        self.log.debug("Sending multicast request - Token: %s, Remote: %s" % (binascii.b2a_hex(request.token).decode('ascii'), request.remote))

        self.protocol.loop.call_later(MULTICAST_REQUEST_TIMEOUT, self._timeout)

        for i in range(5):
            # FIXME that's not what the spec says. what does the spec say?
            yield from asyncio.sleep(i/2)
            self.protocol.send_message(request)

    def handle_response(self, response):
        # not setting requested_hostinfo, that needs to come from the remote
        response.requested_path = self.request.opt.uri_path
        response.requested_query = self.request.opt.get_option(OptionNumber.URI_QUERY) or ()

        # FIXME this should somehow backblock, but it's udp -- maybe rather limit queue length?
        asyncio.Task(self.responses.put(response))

    def _timeout(self):
        self.protocol.outgoing_requests.pop(self.request.token, None)
        self.responses.finish()

class Responder(object):
    """Handler for an incoming request or (in blockwise) a group thereof

    Class includes methods that handle receiving incoming blockwise requests
    (only atomic operation on complete requests), searching for target
    resources, preparing responses and sending outgoing blockwise responses.

    To keep an eye on exchanges going on, a factory for ExchangeMonitor can be
    passed in that generates a monitor for every single message exchange
    created during the response."""

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
            cancel_thoroughly(self._next_block_timeout)

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

    @asyncio.coroutine
    def dispatch_request(self, initial_block):
        """Dispatch incoming request - search context resource tree for
        resource in Uri Path and call proper CoAP Method on it."""

        if self.protocol.serversite is None:
            self.respond_with_error(initial_block, NOT_FOUND, "Context is not a server")
            return

        try:
            needs_blockwise = yield from self.protocol.serversite.needs_blockwise_assembly(initial_block)
        except Exception as e:
            self.respond_with_error(initial_block, INTERNAL_SERVER_ERROR, "")
            self.log.error("An exception occurred while requesting needs_blockwise: %r"%e)
            self.log.exception(e)
            return

        if needs_blockwise:
            self.handle_next_request(initial_block)

            try:
                request = yield from self.app_request
            except asyncio.CancelledError:
                # error has been handled somewhere else
                return
        else:
            request = initial_block

        #TODO: Request with Block2 option and non-zero block number should get error response

        delayed_ack = self.protocol.loop.call_later(EMPTY_ACK_DELAY, self.send_empty_ack, request)

        yield from self.handle_observe_request(request)

        try:
            response = yield from self.protocol.serversite.render(request)
        except error.RenderableError as e:
            self.respond_with_error(request, e.code, e.message)
        except Exception as e:
            self.respond_with_error(request, INTERNAL_SERVER_ERROR, "")
            self.log.error("An exception occurred while rendering a resource: %r"%e)
            self.log.exception(e)
        else:
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
            cancel_thoroughly(delayed_ack)

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
        size_exp = min(request.opt.block2.size_exponent if request.opt.block2 is not None else DEFAULT_BLOCK_SIZE_EXP, DEFAULT_BLOCK_SIZE_EXP)
        if len(self.app_response.payload) > (2 ** (size_exp + 4)):
            first_block = self.app_response._extract_block(0, size_exp)
            self.app_response.opt.block2 = first_block.opt.block2
            self.send_non_final_response(first_block, request)
        else:
            self.send_final_response(app_response, request)

    def process_block2_in_request(self, request):
        """Process incoming request with regard to Block2 option

        Method is recursive - calls itself until all response blocks are sent
        to client."""

        if request.opt.block2 is not None:
            block2 = request.opt.block2
            self.log.debug("Request with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))

            next_block = self.app_response._extract_block(block2.block_number, block2.size_exponent)
            if next_block is None:
                # TODO is this the right error code here?
                self.respond_with_error(request, REQUEST_ENTITY_INCOMPLETE, "Request out of range")
                return
            if next_block.opt.block2.more is True:
                self.app_response.opt.block2 = next_block.opt.block2
                self.send_non_final_response(next_block, request)
            else:
                self.send_final_response(next_block, request)
        else:
            # TODO is this the right error code here?
            self.respond_with_error(request, REQUEST_ENTITY_INCOMPLETE, "Requests after a block2 response must carry the block2 option.")

    def send_non_final_response(self, response, request):
        """Helper method to send a response to client, and setup a timeout for
        client. This also registers the responder with the protocol again to
        receive the next message."""

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

        response.token = request.token
        self.log.debug("Sending token: %s" % (binascii.b2a_hex(response.token).decode('ascii'),))
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

    def send_empty_ack(self, request):
        """Send separate empty ACK when response preparation takes too long.

        Currently, this can happen only once per Responder, that is, when the
        last block1 has been transferred and the first block2 is not ready
        yet."""

        self.log.debug("Response preparation takes too long - sending empty ACK.")
        ack = Message(mtype=ACK, code=EMPTY, payload=b"")
        # not going via send_response because it's all only about the message id
        ack.remote = request.remote
        ack.mid = request.mid
        self.protocol.send_message(ack)
        self._sent_empty_ack = True

    @asyncio.coroutine
    def handle_observe_request(self, request):
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

        if request.code == GET and request.opt.observe == 0 and hasattr(self.protocol.serversite, "add_observation"):
            sobs = ServerObservation(self.protocol, request, self.log)
            yield from self.protocol.serversite.add_observation(request, sobs)
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

        if self._serverobservation is None:
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

class ExchangeMonitor(object):
    """Callback collection interface to keep track of what happens to an
    exchange.

    Callbacks will be called in sequence: ``enqueued{0,1} sent
    retransmitted{0,MAX_RETRANSMIT} (timeout | rst | cancelled | response)``; everything
    after ``sent`` only gets called if the messae that initiated the exchange
    was a CON."""

    def enqueued(self): pass
    def sent(self): pass
    def retransmitted(self): pass
    def timeout(self): pass
    def rst(self): pass
    def cancelled(self): pass
    def response(self, message): pass

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
            self.original_protocol.loop.call_later(cancellation_callback)
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

    class ObservationExchangeMonitor(ExchangeMonitor):
        """These objects feed information about the success or failure of a
        response back to the observation.

        Note that no information flows to the exchange monitor from the
        observation, so they may outlive the observation and need to check if
        it's not already cancelled before cancelling it.
        """
        def __init__(self, observation):
            self.observation = observation
            self.observation.log.info("creating exchange observation monitor")

        # TODO: this should pause/resume furter notifications
        def enqueued(self): pass
        def sent(self): pass

        def rst(self):
            self.observation.log.debug("Observation received RST, cancelling")
            if not self.observation.cancelled:
                self.observation._cancel()

        def timeout(self):
            self.observation.log.debug("Observation received timeout, cancelling")
            if not self.observation.cancelled:
                self.observation._cancel()

class ClientObservation(object):
    def __init__(self, original_request):
        self.original_request = original_request
        self.callbacks = []
        self.errbacks = []

        # the _register and _unregister pair take care that no responses come
        # in after cancellation, but they only start after the initial response
        # (to take care of "resource not observable" errors). while we have
        # those early errors, we need an explicit cancellation indication.
        self.cancelled = False

        self._registry_data = None

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

        @asyncio.coroutine
        def __anext__(self):
            f = self._future
            try:
                result = (yield from self._future)
                if f is self._future:
                    self._future = asyncio.Future()
                return result
            except Exception:
                raise StopAsyncIteration

    def register_callback(self, callback):
        """Call the callback whenever a response to the message comes in, and
        pass the response to it."""
        self.callbacks.append(callback)
        self._set_nonweak()

    def register_errback(self, callback):
        """Call the callback whenever something goes wrong with the
        observation, and pass an exception to the callback. After such a
        callback is called, no more callbacks will be issued."""
        self.errbacks.append(callback)
        self._set_nonweak()

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

    def cancel(self):
        """Cease to generate observation or error events. This will not
        generate an error by itself."""

        assert self.cancelled == False

        # make sure things go wrong when someone tries to continue this
        self.errbacks = None
        self.callbacks = None

        self.cancelled = True

        self._unregister()

    def _register(self, observation_dict, key):
        """Insert the observation into a dict (observation_dict) at the given
        key, and store those details for use during cancellation."""

        if key in observation_dict:
            raise ValueError("Observation conflicts with a registered observation.")

        if self._registry_data is not None:
            raise ValueError("Already registered.")

        self._registry_data = (observation_dict, key)

        observation_dict[key] = weakref.ref(self)

    def _set_nonweak(self):
        """Prevent the observation from being garbage collected (because it has
        actual callbacks). Not reversible right now because callbacks can't be
        deregistered anyway."""
        if self._registry_data and isinstance(self._registry_data[0][self._registry_data[1]], weakref.ref):
            self._registry_data[0][self._registry_data[1]] = lambda self=self: self

    def _unregister(self):
        """Undo the registration done in _register if it was ever done."""

        if self._registry_data is not None:
            del self._registry_data[0][self._registry_data[1]]
            self._registry_data = None

    def __repr__(self):
        return '<%s %s at %#x>'%(type(self).__name__, "(cancelled)" if self.cancelled else "(%s call-, %s errback(s))"%(len(self.callbacks), len(self.errbacks)), id(self))

    def __del__(self):
        if self._registry_data is not None:
            # if we want to go fully gc-driven later, the warning can be
            # dropped -- but for observations it's probably better to
            # explicitly state disinterest.
            logging.warning("Observation deleted without explicit cancellation")
            self._unregister()
