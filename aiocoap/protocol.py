# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains the classes that are responsible for keeping track of messages:

* :class:`Context` roughly represents the CoAP endpoint (basically a UDP
  socket) -- something that can send requests and possibly can answer incoming
  requests.
* a :class:`Request` gets generated whenever a request gets sent to keep
  track of the response
* a :class:`Responder` keeps track of a single incoming request
"""

import random
import struct
import binascii
import functools
import socket
import asyncio

from .util.queuewithend import QueueWithEnd
from .util.asyncio import cancel_thoroughly

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
        self.outgoing_observations = {} #: Observations where this context acts as client. ``(token, remote) -> ClientObservation``

        self.log = logging.getLogger(loggername)

        self.loop = loop or asyncio.get_event_loop()

        self.ready = asyncio.Future() #: Future that gets fullfilled by connection_made (ie. don't send before this is done; handled by ``create_..._context``

    def shutdown(self):
        self.log.debug("Shutting down context")
        for exchange_monitor, cancellable in self._active_exchanges.values():
            if exchange_monitor is not None:
                exchange_monitor.cancelled()
            cancellable.cancel()
        self._active_exchanges = None
        self.transport.close()

    #
    # implementing the typical DatagramProtocol interfaces.
    #
    # note from the documentation: we may rely on connection_made to be called
    # before datagram_received -- but sending immediately after context
    # creation will still fail

    def connection_made(self, transport):
        """Implementation of the DatagramProtocol interface, called by the transport."""
        self.ready.set_result(True)
        self.transport = transport

    def datagram_received(self, data, address):
        """Implementation of the DatagramProtocol interface, called by the transport."""
        self.log.debug("received %r from %s" % (data, address))
        try:
            message = Message.decode(data, address)
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s"%(address,))
            return

        self._dispatch_message(message)

    def error_received(self, exc):
        """Implementation of the DatagramProtocol interface, called by the transport."""
        # TODO: set IP_RECVERR to receive icmp "destination unreachable (port
        # unreachable)" & co to stop retransmitting and err back quickly
        self.log.error("Error received: %s"%exc)

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

        assert message.remote not in self._backlogs
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
            self.log.info("Received %s from %s, but could not match it to a running exchange."%(message.mtype, message.remote))
            return

        exchange_monitor, next_retransmission = self._active_exchanges.pop(key)
        cancel_thoroughly(next_retransmission)
        if exchange_monitor is not None:
            if message.mtype is RST:
                exchange_monitor.rst()
            else:
                exchange_monitor.response(message)
        self.log.debug("Exchange removed, message ID: %d." % message.mid)

        if message.remote not in self._backlogs:
            # if active exchanges were something we could do a
            # .register_finally() on, we could chain them like that; if we
            # implemented anything but NSTART=1, we'll need a more elaborate
            # system anyway
            raise AssertionError("backlogs/active_exchange relation violated (implementation error)")

        # first iteration is sure to happen, others happen only if the enqueued
        # messages were NONs
        while not any(remote == message.remote for remote, mid in self._active_exchanges.keys()):
            if self._backlogs[message.remote] != []:
                next_message, exchange_monitor = self._backlogs[message.remote].pop(0)
                self._send(next_message, exchange_monitor)
            else:
                del self._backlogs[message.remote]
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
            self.transport.sendto(message.encode(), message.remote)
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

        if (response.token, response.remote) in self.outgoing_requests:
            self.outgoing_requests.pop((response.token, response.remote)).handle_response(response)
        elif (response.token, None) in self.outgoing_requests:
            # that's exactly the `MulticastRequest`s so far
            self.outgoing_requests[(response.token, None)].handle_response(response)
        elif (response.token, response.remote) in self.outgoing_observations:
            ## @TODO: deduplication based on observe option value, collecting
            # the rest of the resource if blockwise
            self.outgoing_observations[(response.token, response.remote)].callback(response)

            if response.opt.observe is None:
                self.outgoing_observations[(response.token, response.remote)].error(error.ObservationCancelled())
        else:
            return False

        return True

    #
    # outgoing messages
    #

    def send_message(self, message, exchange_monitor=None):
        """Encode and send message. This takes care of retransmissions (if
        CON), message IDs and rate limiting, but does not hook any events to
        responses. (Use the :class:`Request` class or responding resources
        instead; those are the typical callers of this function.)

        If notification about the progress of the exchange is required, an
        ExchangeMonitor can be passed in, which will receive the appropriate
        callbacks."""

        if message.mtype == CON and message.has_multicast_remote():
            raise ValueError("Refusing to send CON message to multicast address")

        if message.mid is None:
            message.mid = self._next_message_id()

        if message.remote in self._backlogs:
            self.log.debug("Message to %s put into backlog"%(message.remote,))
            if exchange_monitor is not None:
                exchange_monitor.enqueued()
            self._backlogs[message.remote].append((message, exchange_monitor))
        else:
            self._send(message, exchange_monitor)

    def _send(self, message, exchange_monitor=None):
        """Put the message on the wire, starting retransmission timeouts"""

        self.log.debug("Sending message %r" % message)

        if message.mtype is CON:
            self._add_exchange(message, exchange_monitor)

        if exchange_monitor is not None:
            exchange_monitor.sent()

        self._store_response_for_duplicates(message)

        encoded = message.encode()
        self.transport.sendto(encoded, message.remote)

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

    def request(self, request):
        """TODO: create a proper interface to implement and deprecate direct instanciation again"""
        return Request(self, request)

    def multicast_request(self, request):
        return MulticastRequest(self, request).responses

    #
    # convenience methods for class instanciation
    #

    @classmethod
    @asyncio.coroutine
    def create_client_context(cls):
        """Create a context bound to all addresses on a random listening port.

        This is the easiest way to get an context suitable for sending client
        requests.
        """

        loop = asyncio.get_event_loop()

        #transport, protocol = yield from loop.create_datagram_endpoint(cls, family=socket.AF_INET)

        # use the following lines instead, and change the address to `::ffff:127.0.0.1`
        # in order to see acknowledgement handling fail with hybrid stack operation
        transport, protocol = yield from loop.create_datagram_endpoint(cls, family=socket.AF_INET6)
        transport._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        yield from protocol.ready

        return protocol

    @classmethod
    @asyncio.coroutine
    def create_server_context(cls, site, bind=("::", COAP_PORT)):
        """Create an context, bound to all addresses on the CoAP port (unless
        otherwise specified in the ``bind`` argument).

        This is the easiest way to get a context suitable both for sending
        client and accepting server requests."""

        loop = asyncio.get_event_loop()

        transport, protocol = yield from loop.create_datagram_endpoint(lambda: cls(loop, site, loggername="coap-server"), family=socket.AF_INET6)
        transport._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        transport._sock.bind(bind)

        yield from protocol.ready

        return protocol

class BaseRequest(object):
    """Common mechanisms of :class:`Request` and :class:`MulticastRequest`"""

    @asyncio.coroutine
    def _fill_remote(self, request):
        if request.remote is None:
            if request.opt.uri_host:
                ## @TODO this is very rudimentary; happy-eyeballs or
                # similar could be employed.
                addrinfo = yield from self.protocol.loop.getaddrinfo(
                    request.opt.uri_host,
                    request.opt.uri_port or COAP_PORT,
                    family=self.protocol.transport._sock.family,
                    type=0,
                    proto=self.protocol.transport._sock.proto,
                    flags=socket.AI_V4MAPPED,
                    )
                request.remote = addrinfo[0][-1]
            else:
                raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

class Request(BaseRequest, interfaces.Request):
    """Class used to handle single outgoing request.

    Class includes methods that handle sending outgoing blockwise requests and
    receiving incoming blockwise responses."""

    def __init__(self, protocol, app_request, exchange_monitor_factory=(lambda message: None)):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.app_request = app_request
        self._assembled_response = None

        self._exchange_monitor_factory = exchange_monitor_factory

        self._request_transmitted_completely = False

        self._requesttimeout = None

        if self.app_request.code.is_request() is False:
            raise ValueError("Message code is not valid for request")

        self.response = asyncio.Future()
        self.response.add_done_callback(self._response_cancellation_handler)

        asyncio.async(self._init_phase2())

    @asyncio.coroutine
    def _init_phase2(self):
        """Later aspects of initialization that deal more with sending the
        message than with the setup of the requester

        Those are split off into a dedicated function because completion might
        depend on async results."""

        try:
            yield from self._fill_remote(self.app_request)

            size_exp = DEFAULT_BLOCK_SIZE_EXP
            if len(self.app_request.payload) > (2 ** (size_exp + 4)):
                request = self.app_request._extract_block(0, size_exp)
                self.app_request.opt.block1 = request.opt.block1
            else:
                request = self.app_request
                self._request_transmitted_completely = True

            if self.app_request.opt.observe is not None:
                self.observation = ClientObservation(self.app_request)
                self.response.add_done_callback(self.register_observation)

            self.send_request(request)
        except Exception as e:
            self.response.set_exception(e)

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
            self.response.set_exception(error.RequestTimedOut())

        if request.mtype is None:
            request.mtype = CON
        request.token = self.protocol.next_token()

        try:
            self.protocol.send_message(request, self._exchange_monitor_factory(request))
        except Exception as e:
            self.response.set_exception(e)
        else:
            if self._requesttimeout:
                cancel_thoroughly(self._requesttimeout)
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
            self.response.set_exception(UnexpectedBlock1Option())

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
                self.response.set_exception(UnexpectedBlock1Option())

    def process_block2_in_response(self, response):
        """Process incoming response with regard to Block2 option."""

        if response.opt.block2 is not None:
            block2 = response.opt.block2
            self.log.debug("Response with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            if self._assembled_response is not None:
                try:
                    self._assembled_response._append_response_block(response)
                except error.Error as e:
                    self.result.set_exception(e)
            else:
                if block2.block_number == 0:
                    self.log.debug("Receiving blockwise response")
                    self._assembled_response = response
                else:
                    self.response.set_exception(UnexpectedBlock2())
            if block2.more is True:
                self.send_request(self.app_request._generate_next_block2_request(response))
            else:
                self.handle_final_response(self._assembled_response)
        else:
            if self._assembled_response is not None:
                self.log.warning("Server sent non-blockwise response after having started a blockwise transfer. Blockwise transfer cancelled, accepting single response.")
            self.handle_final_response(response)

    def handle_final_response(self, response):
        response.requested_host = self.app_request.opt.uri_host
        response.requested_port = self.app_request.opt.uri_port
        response.requested_path = self.app_request.opt.uri_path
        response.requested_query = self.app_request.opt.get_option(OptionNumber.URI_QUERY) or ()

        self.response.set_result(response)

    def register_observation(self, response_future):
        # we could have this be a coroutine, then it would be launched
        # immediately instead of as add_done_callback to self.response, but it
        # doesn't give an advantage, we'd still have to check for whether the
        # observation has been cancelled before setting an error, and we'd just
        # one more task around
        try:
            response = response_future.result()
        except Exception as e:
            if not self.observation.cancelled:
                self.observation.error(e)
            return

        if response.opt.observe is None:
            if not self.observation.cancelled:
                self.observation.error(error.NotObservable())
        else:
            self.observation._register(self.protocol.outgoing_observations, (response.token, response.remote))

class MulticastRequest(BaseRequest):
    def __init__(self, protocol, request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.request = request

        if self.request.mtype != NON or self.request.code != GET or self.request.payload:
            raise ValueError("Multicast currently only supportet for NON GET")

        self.responses = QueueWithEnd()

        asyncio.async(self._init_phase2())

    @asyncio.coroutine
    def _init_phase2(self):
        """See :meth:`Request._init_phase2`"""
        try:
            yield from self._fill_remote(self.request)

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
        # not setting requested_host / port, that needs to come from the remote
        response.requested_path = self.request.opt.uri_path
        response.requested_query = self.request.opt.get_option(OptionNumber.URI_QUERY) or ()

        # FIXME this should somehow backblock, but it's udp
        asyncio.async(self.responses.put(response))

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
        self.log.debug("New responder created")

        # partial request while more block1 messages are incoming
        self._assembled_request = None
        self.app_response = None
        # that will be passed the single request. take care that this does not
        # linger -- either enqueue with incoming_requests (and a timeout), or
        # send a response which cancels the future.
        self.app_request = asyncio.Future()
        # used to track whether to reply with ACK or CON
        self._sent_empty_ack = False

        self._exchange_monitor_factory = exchange_monitor_factory

        self._next_block_timeout = None

        self.handle_next_request(request)

        asyncio.Task(self.dispatch_request())

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
    def dispatch_request(self):
        """Dispatch incoming request - search context resource tree for
        resource in Uri Path and call proper CoAP Method on it."""

        try:
            request = yield from self.app_request
        except asyncio.CancelledError:
            # error has been handled somewhere else
            return

        if self.protocol.serversite is None:
            self.respond_with_error(request, NOT_FOUND, "Context is not a server")
            return

        #TODO: Request with Block2 option and non-zero block number should get error response
        request.prepath = []
        request.postpath = list(request.opt.uri_path)
        try:
            # TODO: if tree is not known beforehand, this get_resource_for might require yielding from
            resource = self.protocol.serversite.get_resource_for(request)
            unfinished_response = resource.render(request)
        except error.NoResource:
            self.respond_with_error(request, NOT_FOUND, "Error: Resource not found!")
        except error.UnallowedMethod:
            self.respond_with_error(request, METHOD_NOT_ALLOWED, "Error: Method not allowed!")
        except error.UnsupportedMethod:
            self.respond_with_error(request, METHOD_NOT_ALLOWED, "Error: Method not recognized!")
        else:
            delayed_ack = self.protocol.loop.call_later(EMPTY_ACK_DELAY, self.send_empty_ack, request)

            try:
                response = yield from unfinished_response
            except Exception as e:
                self.log.error("An exception occurred while rendering a resource: %r"%e)
                response = Message(code=INTERNAL_SERVER_ERROR)

            if resource.observable and request.code == GET and request.opt.observe is not None:
                self.handle_observe(response, request, resource)

            self.respond(response, request, delayed_ack)

    def respond_with_error(self, request, code, payload):
        """Helper method to send error response to client."""
        payload = payload.encode('ascii')
        self.log.info("Sending error response: %r"%payload)
        response = Message(code=code, payload=payload)
        self.respond(response, request)

    def respond(self, app_response, request, delayed_ack=None):
        """Take application-supplied response and prepare it for sending."""

        # if there was an error, make sure nobody hopes to get a result any more
        self.app_request.cancel()

        self.log.debug("Preparing response...")
        if delayed_ack is not None:
            cancel_thoroughly(delayed_ack)
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

        def timeout_non_final_response(self, key):
            self.log.info("Waiting for next blockwise request timed out")
            self.protocol.incoming_requests.pop(key)
            self.app_request.cancel()

        # we don't want to have this incoming request around forever
        self._next_block_timeout = self.protocol.loop.call_later(MAX_TRANSMIT_WAIT, timeout_non_final_response, self, key)
        self.protocol.incoming_requests[key] = self

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

    def handle_observe(self, app_response, request, resource):
        """Intermediate state of sending a response that the response will go
        through if it might need to be processed for observation. This both
        handles the implications for notification sending and adds the observe
        response option."""

        observation_identifier = (request.remote, request.token)

        if app_response.code not in (VALID, CONTENT):
            if observation_identifier in resource.observers:
                ## @TODO cancel observation
                pass
            return

        if observation_identifier in resource.observers:
            pass ## @TODO renew that observation (but keep in mind that whenever we send a notification, the original message is replayed)
        else:
            ServerObservation(self.protocol, request, self.log, observation_identifier, resource)

        app_response.opt.observe = resource.observe_index

        if request.mtype is None:
            # this is the indicator that the request was just injected
            app_response.mtype = CON

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
    ServerObservation object attached to a Resource in .observers[(address,
    token)].

    It keeps a complete copy of the original request for simplicity (while it
    actually would only need parts of that request, like the accept option)."""

    def __init__(self, original_protocol, original_request, requester_log, identifier, resource):
        self.original_protocol = original_protocol
        self.original_request = original_request
        self.log = requester_log.getChild("observation")

        self._identifier = identifier
        self._resource = resource
        self._resource.observers[self._identifier] = self

    def trigger(self):
        # bypassing parsing and duplicate detection, pretend the request came in again
        self.log.debug("Server observation triggered, injecting original request %r again"%self.original_request)
        # TODO this indicates that the request is injected -- overloading .mtype is not the cleanest thing to do hee
        self.original_request.mtype = None
        self.original_request.mid = None

        # the prediction is that the factory will be called exactly once, as no
        # blockwise is involved
        Responder(self.original_protocol, self.original_request, lambda message: self.ObservationExchangeMonitor(self))

    def cancel(self):
        # this should lead to the object being garbage collected pretty soon,
        # as the caller (typically ObservationExchangeMonitor in its
        # rst/timeout method) gets deref'd when the exchange ends, and the
        # resource's observers list is the only place the observation is stored

        if self._resource.observers.get(self._identifier, None) != self:
            # we accept both duplicate removals (eg if two notifications are in
            # the air and both get cancelled); it's ok if another observation
            # took our place, we won't drop that.
            pass
        else:
            del self._resource.observers[self._identifier]

    class ObservationExchangeMonitor(ExchangeMonitor):
        def __init__(self, observation):
            self.observation = observation
            self.observation.log.info("creating exchange observation monitor")

        # TODO: this should pause/resume furter notifications
        def enqueued(self): pass
        def sent(self): pass

        def rst(self):
            self.observation.log.debug("Observation received RST, cancelling")
            self.observation.cancel()

        def timeout(self):
            self.observation.log.debug("Observation received timeout, cancelling")
            self.observation.cancel()

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

    def register_callback(self, callback):
        """Call the callback whenever a response to the message comes in, and
        pass the response to it."""
        self.callbacks.append(callback)

    def register_errback(self, callback):
        """Call the callback whenever something goes wrong with the
        observation, and pass an exception to the callback. After such a
        callback is called, no more callbacks will be issued."""
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

    def cancel(self):
        """Cease to generate observation or error events. This will not
        generate an error by itself."""

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

        observation_dict[key] = self

    def _unregister(self):
        """Undo the registration done in _register if it was ever done."""

        if self._registry_data is not None:
            del self._registry_data[0][self._registry_data[1]]
