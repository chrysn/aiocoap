'''
Created on 08-09-2012

@author: Maciej Wasilak
'''
import random
import struct
import binascii
import ipaddress

import asyncio

from queuewithend import QueueWithEnd

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

import iot.error

from .numbers import *
from .message import Message

def is_multicast_remote(remote):
    """Return True if the described remote (typically a (host, port) tuple) needs to be considered a multicast remote."""
    host = remote[0]
    address = ipaddress.ip_address(remote[0])
    return address.is_multicast

def uriPathAsString(segment_list):
    return '/' + '/'.join(segment_list)


class Coap(asyncio.DatagramProtocol):

    def __init__(self, endpoint, loop, loggername="coap"):
        """Initialize a CoAP protocol instance."""
        self.message_id = random.randint(0, 65535)
        self.token = random.randint(0, 65535)
        self.endpoint = endpoint
        self.recent_messages = {}  # recently received messages (identified by message ID and remote)
        self.active_exchanges = {}  # active exchanges i.e. sent CON messages (identified by message ID and remote)
        self.backlogs = {} # per-remote list of backlogged packages (keys exist iff there is an active_exchange with that node)
        self.outgoing_requests = {}  # unfinished outgoing requests (identified by token and remote)
        self.incoming_requests = {}  # unfinished incoming requests (identified by path tuple and remote)
        self.outgoing_observations = {} # observations where this node is the client. (token, remote) -> ClientObservation

        self.log = logging.getLogger(loggername)

        self.loop = loop

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, host_and_port):
        (host, port) = host_and_port
        self.log.debug("received %r from %s:%d" % (data, host, port))
        try:
            message = Message.decode(data, (host, port), self)
        except iot.error.UnparsableMessage:
            logging.warning("Ignoring unparsable message from %s:%d"%(host, port))
            return
        if self.deduplicateMessage(message) is True:
            return
        if message.code.is_request():
            self.processRequest(message)
        elif message.code.is_response():
            self.processResponse(message)
        elif message.code is EMPTY:
            self.processEmpty(message)

    def deduplicateMessage(self, message):
        """Check incoming message if it's a duplicate.

           Duplicate is a message with the same Message ID (mid)
           and sender (remote), as message received within last
           EXCHANGE_LIFETIME seconds (usually 247 seconds)."""

        key = (message.mid, message.remote)
        self.log.debug("Incoming Message ID: %d" % message.mid)
        if key in self.recent_messages:
            if message.mtype is CON:
                if len(self.recent_messages[key]) == 3:
                    self.log.info('Duplicate CON received, sending old response again')
                    self.sendMessage(self.recent_messages[key][2])
                else:
                    self.log.info('Duplicate CON received, no response to send')
            else:
                self.log.info('Duplicate NON, ACK or RST received')
            return True
        else:
            self.log.debug('New unique message received')
            expiration = self.loop.call_later(EXCHANGE_LIFETIME, self.removeMessageFromRecent, key)
            self.recent_messages[key] = (message, expiration)
            return False

    def removeMessageFromRecent(self, key):
        """Remove Message ID+Remote combination from
           recent messages cache."""
        self.recent_messages.pop(key)

    def processResponse(self, response):
        """Method used for incoming response processing."""
        if response.mtype is RST:
            return
        if response.mtype is ACK:
            if response.mid in self.active_exchanges:
                self.removeExchange(response)
            else:
                return
        self.log.debug("Received Response, token: %s, host: %s, port: %s" % (binascii.b2a_hex(response.token), response.remote[0], response.remote[1]))
        if (response.token, response.remote) in self.outgoing_requests:
            self.outgoing_requests.pop((response.token, response.remote)).handleResponse(response)
            if response.mtype is CON:
                #TODO: Some variation of sendEmptyACK should be used
                ack = Message(mtype=ACK, mid=response.mid, code=EMPTY, payload="")
                ack.remote = response.remote
                self.sendMessage(ack)
        elif (response.token, None) in self.outgoing_requests:
            # that's exactly the `MulticastRequester`s so far
            self.outgoing_requests[(response.token, None)].handleResponse(response)
        elif (response.token, response.remote) in self.outgoing_observations:
            ## @TODO: deduplication based on observe option value, collecting
            # the rest of the resource if blockwise
            self.outgoing_observations[(response.token, response.remote)].callback(response)

            if response.mtype is CON:
                #TODO: Some variation of sendEmptyACK should be used (as above)
                ack = Message(mtype=ACK, mid=response.mid, code=EMPTY, payload="")
                ack.remote = response.remote
                self.sendMessage(ack)

            if response.opt.observe is None:
                self.outgoing_observations[(response.token, response.remote)].error(iot.error.ObservationCancelled())
        else:
            self.log.info("Response not recognized - sending RST.")
            rst = Message(mtype=RST, mid=response.mid, code=EMPTY, payload='')
            rst.remote = response.remote
            self.sendMessage(rst)

    def processRequest(self, request):
        """Method used for incoming request processing."""
        if request.mtype not in (CON, NON):
            response = Message(code=BAD_REQUEST, payload='Wrong message type for request!')
            self.respond(response, request)
            return
        if (tuple(request.opt.uri_path), request.remote) in self.incoming_requests:
            self.log.debug("Request pertains to earlier blockwise requests.")
            self.incoming_requests.pop((tuple(request.opt.uri_path), request.remote)).handleNextRequest(request)
        else:
            responder = Responder(self, request)

    def processEmpty(self, message):
        if message.mtype is CON:
            self.log.info('Empty CON message received (CoAP Ping) - replying with RST.')
            rst = Message(mtype=RST, mid=message.mid, code=EMPTY, payload='')
            rst.remote = message.remote
            self.sendMessage(rst)
        #TODO: passing ACK/RESET info to application
        #Currently it doesn't matter if empty ACK or RST is received - in both cases exchange has to be removed
        if message.mid in self.active_exchanges and message.mtype in (ACK, RST):
            self.removeExchange(message)

    def sendMessage(self, message):
        """Set Message ID, encode and send message.
           Also if message is Confirmable (CON) add Exchange"""
        host, port = message.remote

        if message.mtype == CON and is_multicast_remote(message.remote):
            raise ValueError("Refusing to send CON message to multicast address")

        self.log.debug("Sending message to %s:%d" % (host, port))
        recent_key = (message.mid, message.remote)
        if recent_key in self.recent_messages:
            if len(self.recent_messages[recent_key]) != 3:
                self.recent_messages[recent_key] = self.recent_messages[recent_key] + (message,)

        if message.mid is None:
            message.mid = self.nextMessageID()

        self.enqueueForSending(message)

    def enqueueForSending(self, message):
        if message.remote in self.backlogs:
            self.log.debug("Message to %s put into backlog"%(message.remote,))
            self.backlogs[message.remote].append(message)
        else:
            self.send(message)

    def send(self, message):
        if message.mtype is CON:
            self.addExchange(message)
        msg = message.encode()
        self.transport.sendto(msg, message.remote)
        self.log.debug("Message %r sent successfully" % msg)

    def nextMessageID(self):
        """Reserve and return a new message ID."""
        message_id = self.message_id
        self.message_id = 0xFFFF & (1 + self.message_id)
        return message_id

    def nextToken(self):
        """Reserve and return a new Token for request."""
        #TODO: add proper Token handling
        token = self.token
        self.token = (self.token + 1) & 0xffffffffffffffff
        return binascii.a2b_hex("%08x"%self.token)

    def addExchange(self, message):
        """Add an "exchange" for outgoing CON message.

           CON (Confirmable) messages are automatically
           retransmitted by protocol until ACK or RST message
           with the same Message ID is received from target host."""

        self.backlogs.setdefault(message.remote, [])

        timeout = random.uniform(ACK_TIMEOUT, ACK_TIMEOUT * ACK_RANDOM_FACTOR)
        retransmission_counter = 0
        next_retransmission = self.loop.call_later(timeout, self.retransmit, message, timeout, retransmission_counter)
        self.active_exchanges[message.mid] = (message, next_retransmission)
        self.log.debug("Exchange added, Message ID: %d." % message.mid)

    def removeExchange(self, message):
        """Remove exchange from active exchanges and cancel the timeout
           to next retransmission."""
        self.active_exchanges.pop(message.mid)[1].cancel()
        self.log.debug("Exchange removed, Message ID: %d." % message.mid)

        if message.remote not in self.backlogs:
            # if active exchanges were something we could do a
            # .register_finally() on, we could chain them like that; if we
            # implemented anything but NSTART=1, we'll need a more elaborate
            # system anyway
            raise AssertionError("backlogs/active_exchange relation violated (implementation error)")

        while not any(m.remote == message.remote for m, t in self.active_exchanges.values()):
            if self.backlogs[message.remote] != []:
                next_message = self.backlogs[message.remote].pop(0)
                self.send(next_message)
            else:
                del self.backlogs[message.remote]
                break

    def retransmit(self, message, timeout, retransmission_counter):
        """Retransmit CON message that has not been ACKed or RSTed."""
        self.active_exchanges.pop(message.mid)
        if retransmission_counter < MAX_RETRANSMIT:
            self.transport.sendto(message.encode(), message.remote)
            retransmission_counter += 1
            timeout *= 2
            next_retransmission = self.loop.call_later(timeout, self.retransmit, message, timeout, retransmission_counter)
            self.active_exchanges[message.mid] = (message, next_retransmission)
            self.log.info("Retransmission, Message ID: %d." % message.mid)
        else:
            pass
            #TODO: error handling (especially for requests)

    def request(self, request, observeCallback=None, block1Callback=None, block2Callback=None,
                observeCallbackArgs=None, block1CallbackArgs=None, block2CallbackArgs=None,
                observeCallbackKeywords=None, block1CallbackKeywords=None, block2CallbackKeywords=None):
        """Send a request.

           This is a method that should be called by user app."""
        return Requester(self, request, observeCallback, block1Callback, block2Callback,
                         observeCallbackArgs, block1CallbackArgs, block2CallbackArgs,
                         observeCallbackKeywords, block1CallbackKeywords, block2CallbackKeywords).response

    def multicast_request(self, request):
        return MulticastRequester(self, request).responses


class Requester(object):
    """Class used to handle single outgoing request.

       Class includes methods that handle sending
       outgoing blockwise requests and receiving incoming
       blockwise responses."""

    def __init__(self, protocol, app_request, observeCallback, block1Callback, block2Callback,
                       observeCallbackArgs, block1CallbackArgs, block2CallbackArgs,
                       observeCallbackKeywords, block1CallbackKeywords, block2CallbackKeywords):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.app_request = app_request
        self.assembled_response = None
        assert observeCallback == None or callable(observeCallback)
        assert block1Callback == None or callable(block1Callback)
        assert block2Callback == None or callable(block2Callback)
        self.cbs = ((block1Callback, block1CallbackArgs, block1CallbackKeywords),
                    (block2Callback, block2CallbackArgs, block2CallbackKeywords))
        if app_request.opt.observe is not None:
            self.observation = ClientObservation(app_request)
            if observeCallback is not None:
                self.observation.register_callback(lambda result, cb=observeCallback, args=observeCallbackArgs or (), kwargs=observeCallbackKeywords or {}: cb(result, *args, **kwargs))
        if self.app_request.code.is_request() is False:
            raise ValueError("Message code is not valid for request")
        size_exp = DEFAULT_BLOCK_SIZE_EXP
        if len(self.app_request.payload) > (2 ** (size_exp + 4)):
            raise Exception("multiblock handling broken, length %s"%len(self.app_request.payload))
            request = self.app_request.extractBlock(0, size_exp)
            self.app_request.opt.block1 = request.opt.block1
        else:
            request = self.app_request

        self.response = self.sendRequest(request)
        # ASYNCIO FIXME chained deferreds
        #self.deferred.add_done_callback(self.processBlock1InResponse)
        #self.deferred.add_done_callback(self.processBlock2InResponse)

    def sendRequest(self, request):
        """Send a request or single request block.

           This method is used in 3 situations:
           - sending non-blockwise request
           - sending blockwise (Block1) request block
           - asking server to send blockwise (Block2) response block
        """

        def cancelRequest(d):
            """Clean request after cancellation from user application."""

            if d.cancelled():
                self.log.debug("Request cancelled")
                # actually, it might be a good idea to always do this here and nowhere else
                self.protocol.outgoing_requests.pop((request.token, request.remote))

        def timeoutRequest(d):
            """Clean the Request after a timeout."""

            self.log.info("Request timed out")
            del self.protocol.outgoing_requests[(request.token, request.remote)]
            d.set_exception(iot.error.RequestTimedOut())

        def gotResult(result):
            timeout.cancel()

        if request.mtype is None:
            request.mtype = CON
        request.token = self.protocol.nextToken()
        try:
            self.protocol.sendMessage(request)
        except Exception as e:
            f = asyncio.Future()
            f.set_exception(e)
            return f
        else:
            d = asyncio.Future()
            d.add_done_callback(cancelRequest)
            timeout = self.protocol.loop.call_later(REQUEST_TIMEOUT, timeoutRequest, d)
            d.add_done_callback(gotResult)
            self.protocol.outgoing_requests[(request.token, request.remote)] = self
            self.log.debug("Sending request - Token: %s, Host: %s, Port: %s" % (binascii.b2a_hex(request.token), request.remote[0], request.remote[1]))
            if hasattr(self, 'observation'):
                d.add_done_callback(self.registerObservation)
            return d

    def handleResponse(self, response):
        response.requested_path = self.app_request.opt.uri_path
        response.requested_query = self.app_request.opt.getOption(OptionNumber.URI_QUERY) or ()

        d, self.response = self.response, None
        d.set_result(response)

    def registerObservation(self, response_future):
        try:
            response = response_future.result()
        except Exception as e:
            if not self.observation.cancelled:
                self.observation.error(e)
            return

        if response.opt.observe is None:
            if not self.observation.cancelled:
                self.observation.error(iot.error.NotObservable())
        else:
            self.observation._register(self.protocol.outgoing_observations, (response.token, response.remote))

    def processBlock1InResponse(self, response_future):
        """Process incoming response with regard to Block1 option.

           Method is called for all responses, with or without Block1
           option.

           Method is recursive - calls itself until all request blocks
           are sent."""

        raise NotImplementedError("Not ported to asyncio yet")

        if response.opt.block1 is not None:
            block1 = response.opt.block1
            self.log.debug("Response with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))
            if block1.block_number == self.app_request.opt.block1.block_number:
                if block1.size_exponent < self.app_request.opt.block1.size_exponent:
                    next_number = (self.app_request.opt.block1.block_number + 1) * 2 ** (self.app_request.opt.block1.size_exponent - block1.size_exponent)
                    next_block = self.app_request.extractBlock(next_number, block1.size_exponent)
                else:
                    next_block = self.app_request.extractBlock(self.app_request.opt.block1.block_number + 1, block1.size_exponent)
                if next_block is not None:
                    self.app_request.opt.block1 = next_block.opt.block1
                    block1Callback, args, kw = self.cbs[0]
                    if block1Callback is None:
                        return self.sendNextRequestBlock(None, next_block)
                    else:
                        args = args or ()
                        kw = kw or {}
                        d = block1Callback(response, *args, **kw)
                        d.addCallback(self.sendNextRequestBlock, next_block)
                        return d
                else:
                    if block1.more is False:
                        return defer.succeed(response)
                    else:
                        return defer.fail()
            else:
                return defer.fail()
        else:
            if self.app_request.opt.block1 is None:
                return defer.succeed(response)
            else:
                return defer.fail()

    def sendNextRequestBlock(self, result, next_block):
        """Helper method used for sending request blocks."""
        self.log.debug("Sending next block of blockwise request.")
        self.deferred = self.sendRequest(next_block)
        self.deferred.add_done_callback(self.processBlock1InResponse)
        return self.deferred

    def processBlock2InResponse(self, response_future):
        """Process incoming response with regard to Block2 option.

           Method is called for all responses, with or without Block2
           option.

           Method is recursive - calls itself until all response blocks
           from server are received."""

        response = response_future.result()

        if response.opt.block2 is not None:
            block2 = response.opt.block2
            self.log.debug("Response with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            if self.assembled_response is not None:
                try:
                    self.assembled_response.appendResponseBlock(response)
                except iot.error.Error as e:
                    return defer.fail(e)
            else:
                if block2.block_number is 0:
                    self.log.debug("Receiving blockwise response")
                    self.assembled_response = response
                else:
                    self.log.warning("ProcessBlock2 error: transfer started with nonzero block number.")
                    return defer.fail()
            if block2.more is True:
                request = self.app_request.generateNextBlock2Request(response)
                block2Callback, args, kw = self.cbs[1]
                # ASYNCIO FIXME deferred return
                if block2Callback is None:
                    return self.askForNextResponseBlock(None, request)
                else:
                    args = args or ()
                    kw = kw or {}
                    d = block2Callback(response, *args, **kw)
                    d.addCallback(self.askForNextResponseBlock, request)
                    return d
            else:
                return defer.succeed(self.assembled_response)
        else:
            if self.assembled_response is None:
                return defer.succeed(response)
            else:
                return defer.fail(iot.error.MissingBlock2Option)

    def askForNextResponseBlock(self, result, request):
        """Helper method used to ask server to send next response block."""
        self.log.debug("Requesting next block of blockwise response.")
        self.deferred = self.sendRequest(request)
        self.deferred.addCallback(self.processBlock2InResponse)
        return self.deferred

class MulticastRequester(object):
    def __init__(self, protocol, request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.request = request

        if self.request.mtype != NON or self.request.code != GET or self.request.payload:
            raise ValueError("Multicast currently only supportet for NON GET")

        self.responses = QueueWithEnd()
        self.sendRequest(request)

    def sendRequest(self, request):
        request.token = self.protocol.nextToken()

        try:
            self.protocol.sendMessage(request)
        except Exception as e:
            self.responses.put_exception(e)
            return

        self.protocol.outgoing_requests[(request.token, None)] = self
        self.log.debug("Sending multicast request - Token: %s, Remote: %s" % (binascii.b2a_hex(request.token), request.remote))

        self.protocol.loop.call_later(MULTICAST_REQUEST_TIMEOUT, self._timeout)

    def handleResponse(self, response):
        response.requested_path = self.request.opt.uri_path
        response.requested_query = self.request.opt.getOption(OptionNumber.URI_QUERY) or ()

        # FIXME this should somehow backblock, but it's udp
        asyncio.async(self.responses.put(response))

    def _timeout(self):
        self.protocol.outgoing_requests.pop(self.request.token, None)
        self.responses.finish()

class Responder(object):
    """Class used to handle single incoming request.

       Class includes methods that handle receiving
       incoming blockwise requests, searching for target
       resources, preparing responses and sending outgoing
       blockwise responses.
       """

    def __init__(self, protocol, request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.assembled_request = None
        self.app_response = None
        self.log.debug("Request doesn't pertain to earlier blockwise requests.")
        self.all_blocks_arrived = asyncio.Future()

        asyncio.Task(self.dispatchRequest(self.all_blocks_arrived))

        self.processBlock1InRequest(request)

    def processBlock1InRequest(self, request):
        """Process incoming request with regard to Block1 option.

           Method is recursive - calls itself until all request blocks
           are received."""
        if request.opt.block1 is not None:
            block1 = request.opt.block1
            self.log.debug("Request with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))
            if block1.block_number == 0:
                #TODO: Check if resource is available - if not send error immediately
                #TODO: Check if method is allowed - if not send error immediately
                self.log.debug("New or restarted incoming blockwise request.")
                self.assembled_request = request
            else:
                try:
                    self.assembled_request.appendRequestBlock(request)
                except (iot.error.NotImplemented, AttributeError):
                    self.respondWithError(request, NOT_IMPLEMENTED, "Error: Request block received out of order!")
                    return defer.fail(iot.error.NotImplemented())
                    #raise iot.error.NotImplemented
            if block1.more is True:
                #TODO: SUCCES_CODE Code should be either Changed or Created - Resource check needed
                #TODO: SIZE_CHECK1 should check if the size of incoming payload is still acceptable
                #TODO: SIZE_CHECK2 should check if Size option is present, and reject the resource if size too large
                return self.acknowledgeRequestBlock(request)
            else:
                self.log.debug("Complete blockwise request received.")
                return defer.succeed(self.assembled_request)
        else:
            if self.assembled_request is not None:
                self.log.warning("Non-blockwise request received during blockwise transfer. Blockwise transfer cancelled.")
            self.all_blocks_arrived.set_result(request)

    def acknowledgeRequestBlock(self, request):
        """Helper method used to ask client to send next request block."""
        self.log.debug("Sending block acknowledgement (allowing client to send next block).")
        response = request.generateNextBlock1Response()
        self.deferred = self.sendNonFinalResponse(response, request)
        self.deferred.add_done_callback(self.processBlock1InRequest)
        return self.deferred

    def dispatchRequest(self, request):
        """Dispatch incoming request - search endpoint
           resource tree for resource in Uri Path
           and call proper CoAP Method on it."""
    @asyncio.coroutine
    def dispatchRequest(self, request_future):
        """Dispatch incoming request - search endpoint
           resource tree for resource in Uri Path
           and call proper CoAP Method on it."""

        try:
            request = yield from request_future
        except iot.NotImplementedError as e:
            """Handle (silently ignore) request errors related
               to Block1. Currently it's used only to ignore
               requests which are send non-sequentially"""
            self.log.error("Block1 assembly on request failed: %r", e)
            return

        #TODO: Request with Block2 option and non-zero block number should get error response
        request.prepath = []
        request.postpath = request.opt.uri_path
        try:
            resource = self.protocol.endpoint.getResourceFor(request)
            unfinished_response = resource.render(request)
        except iot.error.NoResource:
            self.respondWithError(request, NOT_FOUND, "Error: Resource not found!")
        except iot.error.UnallowedMethod:
            self.respondWithError(request, METHOD_NOT_ALLOWED, "Error: Method not allowed!")
        except iot.error.UnsupportedMethod:
            self.respondWithError(request, METHOD_NOT_ALLOWED, "Error: Method not recognized!")
        else:
            delayed_ack = self.protocol.loop.call_later(EMPTY_ACK_DELAY, self.sendEmptyAck, request)

            try:
                response = yield from unfinished_response
            except Exception as e:
                self.log.error("An exception occurred while rendering a resource: %r"%e)
                response = Message(code=iot.coap.INTERNAL_SERVER_ERROR)

            if resource.observable and request.code == GET and request.opt.observe is not None:
                self.handleObserve(response, request, resource)

            self.respond(response, request, delayed_ack)

    def respondWithError(self, request, code, payload):
        """Helper method to send error response to client."""
        payload = payload.encode('ascii')
        self.log.info("Sending error response: %r"%payload)
        response = Message(code=code, payload=payload)
        self.respond(response, request)
        return

    def handleObserve(self, app_response, request, resource):
        """Intermediate state of sending a response that the response will go
        through if it might need to be processed for observation. This both
        handles the implications for notification sending and adds the observe
        response option."""

        observation_identifier = (request.remote, request.token)

        if app_response.code not in (VALID, CONTENT):
            if observation_identifier in resource.observers:
                ## @TODO cancel observation
                pass

        if observation_identifier in resource.observers:
            pass ## @TODO renew that observation (but keep in mind that whenever we send a notification, the original message is replayed)
        else:
            obs = ServerObservation(request)
            resource.observers[observation_identifier] = obs

        app_response.opt.observe = resource.observe_index


    def respond(self, app_response, request, delayed_ack=None):
        """Take application-supplied response and prepare it
           for sending."""

        self.log.debug("Preparing response...")
        if delayed_ack is not None:
            delayed_ack.cancel()
        self.app_response = app_response
        size_exp = min(request.opt.block2.size_exponent if request.opt.block2 is not None else DEFAULT_BLOCK_SIZE_EXP, DEFAULT_BLOCK_SIZE_EXP)
        if len(self.app_response.payload) > (2 ** (size_exp + 4)):
            response = self.app_response.extractBlock(0, size_exp)
            self.app_response.opt.block2 = response.opt.block2
            self.sendResponseBlock(response, request)
        else:
            self.sendResponse(app_response, request)

    def processBlock2InRequest(self, request_future):
        """Process incoming request with regard to Block2 option.

           Method is recursive - calls itself until all response blocks
           are sent to client."""

        request = request_future.result()

        if request.opt.block2 is not None:
            block2 = request.opt.block2
            self.log.debug("Request with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            sent_length = (2 ** (self.app_response.opt.block2.size_exponent + 4)) * (self.app_response.opt.block2.block_number + 1)
            #TODO: compare block size of request and response - calculate new block_number if necessary
            if (2 ** (block2.size_exponent + 4)) * block2.block_number == sent_length:
                next_block = self.app_response.extractBlock(block2.block_number, block2.size_exponent)
                if next_block is None:
                    self.log.warning("Block out of range")
                    # ASYNCIO FIXME deferred return
                    return defer.fail()
                if next_block.opt.block2.more is True:
                    self.app_response.opt.block2 = next_block.opt.block2
                    return self.sendResponseBlock(next_block, request)
                else:
                    self.sendResponse(next_block, request)
                    return defer.succeed(None)
            else:
                self.log.warning("Incorrect block number requested")
                return defer.fail()
        else:
            return defer.fail()

    def sendResponseBlock(self, response_block, request):
        """Helper method to send next response block to client."""
        self.log.debug("Sending response block.")
        self.deferred = self.sendNonFinalResponse(response_block, request)
        self.deferred.add_done_callback(self.processBlock2InRequest)
        return self.deferred

    def sendNonFinalResponse(self, response, request):
        """Helper method to send, a response to client, and setup
           a timeout for client."""

        def cancelNonFinalResponse(d):
            if d.cancelled():
                self.log.debug("Waiting for next client request cancelled")
                self.protocol.incoming_requests.pop((tuple(request.opt.uri_path), request.remote))

        def timeoutNonFinalResponse(d):
            """Clean the Response after a timeout."""

            self.log.info("Waiting for next blockwise request timed out")
            self.protocol.incoming_requests.pop((tuple(request.opt.uri_path), request.remote))
            d.set_exception(iot.error.WaitingForClientTimedOut())

        def gotResult(result):
            timeout.cancel()

        d = asyncio.Future()
        d.add_done_callback(cancelNonFinalResponse)
        timeout = self.protocol.loop.call_later(MAX_TRANSMIT_WAIT, timeoutNonFinalResponse, d)
        d.add_done_callback(gotResult)
        self.protocol.incoming_requests[(tuple(request.opt.uri_path), request.remote)] = self
        self.sendResponse(response, request)
        return d

    def handleNextRequest(self, request):
        d, self.deferred = self.deferred, None
        d.callback(request)

    def sendResponse(self, response, request):
        """Send a response or single response block.

           This method is used in 4 situations:
           - sending success non-blockwise response
           - asking client to send blockwise (Block1) request block
           - sending blockwise (Block2) response block
           - sending any error response
        """
        #if response.code.is_response() is False:
            #raise ValueError("Message code is not valid for a response.")
        response.token = request.token
        self.log.debug("Sending token: %s" % (response.token))
        response.remote = request.remote
        if request.opt.block1 is not None:
            response.opt.block1 = request.opt.block1
        if response.mtype is None:
            if request.response_type is None:
                if request.mtype is CON:
                    response.mtype = ACK
                else:
                    response.mtype = NON
            elif request.response_type is ACK:
                response.mtype = CON
            else:
                raise Exception()
        request.response_type = response.mtype
        if response.mid is None:
            if response.mtype in (ACK, RST):
                response.mid = request.mid
        self.log.debug("Sending response, type = %s (request type = %s)" % (response.mtype.name, request.mtype.name))
        self.protocol.sendMessage(response)

    def sendEmptyAck(self, request):
        """Send separate empty ACK when response preparation takes too long."""
        self.log.debug("Response preparation takes too long - sending empty ACK.")
        ack = Message(mtype=ACK, code=EMPTY, payload="")
        self.respond(ack, request)

class ServerObservation(object):
    """An active CoAP observation inside a server is described as a
    ServerObservation object attached to a Resource in .observers[(address,
    token)].

    It keeps a complete copy of the original request for simplicity (while it
    actually would only need parts of that request, like the accept option)."""

    def __init__(self, original_request):
        self.original_request = original_request

    def trigger(self):
        # bypassing parsing and duplicate detection, pretend the request came in again
        print("triggering retransmission with original request %r (will set response_type to ACK)"%vars(self.original_request))
        self.original_request.response_type = ACK # trick responder into sending CON
        Responder(self.original_request.protocol, self.original_request)
        ## @TODO pass a callback down to the exchange -- if it gets a RST, we have to unregister

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
