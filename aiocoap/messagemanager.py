# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains all internals needed to manage messages on unreliable
transports, ie. everything that deals in message types or Message IDs.

Currently, it also provides the mechanisms for managing tokens, but those will
be split into dedicated classes.
"""

import asyncio
import functools
import random
from typing import Dict, Tuple, Optional

from . import error
from . import interfaces
from .interfaces import EndpointAddress
from .message import Message
from .numbers.types import CON, ACK, RST, NON
from .numbers.codes import EMPTY
from .numbers.constants import (EXCHANGE_LIFETIME, ACK_TIMEOUT, EMPTY_ACK_DELAY,
        MAX_RETRANSMIT, ACK_RANDOM_FACTOR)


class MessageManager(interfaces.TokenInterface, interfaces.MessageManager):
    """This MessageManager Drives a message interface following the rules of
    RFC7252 CoAP over UDP.

    It takes care of picking message IDs (mid) for outgoing messages,
    retransmitting CON messages, and to react appropriately to incoming
    messages' type, sending ACKs either immediately or later.

    It creates piggy-backed responses by keeping an eye on the tokens the
    messages are sent with, but otherwise ignores the tokens. (It inspects
    tokens *only* where required by its sub-layer).
    """

    def __init__(self, token_manager):
        self.token_manager = token_manager

        self.message_id = random.randint(0, 65535)
        #: Tracker of recently received messages (by remote and message ID).
        #: Maps them to a response message when one is already known.
        self._recent_messages: Dict[Tuple[EndpointAddress, int], Optional[Message]] = {}
        self._active_exchanges = {}  #: active exchanges i.e. sent CON messages (remote, message-id): (messageerror_monitor monitor, cancellable timeout)
        self._backlogs = {} #: per-remote list of (backlogged package, messageerror_monitor) tupless (keys exist iff there is an active_exchange with that node)

        #: Maps pending remote/token combinations to the MID a response can be
        #: piggybacked on, and the timeout that should be cancelled if it is.
        self._piggyback_opportunities: Dict[Tuple[EndpointAddress, bytes], (int, asyncio.TimerHandle)] = {}

        self.log = token_manager.log
        self.loop = token_manager.loop

        #self.message_interface = … -- needs to be set post-construction, because the message_interface in its constructor already needs to get its manager

    def __repr__(self):
        return '<%s for %s>' % (type(self).__name__, getattr(self, 'message_interface', '(unbound)'))

    @property
    def client_credentials(self):
        return self.token_manager.client_credentials

    async def shutdown(self):
        for messageerror_monitor, cancellable in self._active_exchanges.values():
            # Not calling messageerror_monitor: This is not message specific,
            # and its shutdown will take care of these things
            cancellable.cancel()
        self._active_exchanges = None

        await self.message_interface.shutdown()

    #
    # implementing the MessageManager interface
    #

    def dispatch_message(self, message):
        """Feed a message through the message-id, message-type and message-code
        sublayers of CoAP"""

        self.log.debug("Incoming message %r", message)
        if message.code.is_request():
            # Responses don't get deduplication because they "are idempotent or
            # can be handled in an idempotent fashion" (RFC 7252 Section 4.5).
            # This means that a separate response may get a RST when it is
            # arrives at the aiocoap client twice. Note that this does not
            # impede the operation of observations: Their token is still active
            # so they are ACK'd, and deduplication based on observation numbers
            # filters out the rest.
            #
            # This saves memory, and allows stateful transports to be shut down
            # expeditiously unless kept alive by something else (otherwise,
            # they'd linger for EXCHANGE_LIFETIME with no good reason).
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
                    self._send_empty_ack(message.remote, message.mid, reason="acknowledging incoming response")
            else:
                if message.remote.is_multicast_locally:
                    self.log.info("Ignoring response incoming with multicast destination.")
                else:
                    self.log.info("Response not recognized - sending RST.")
                    rst = Message(mtype=RST, mid=message.mid, code=EMPTY, payload='')
                    rst.remote = message.remote.as_response_address()
                    self._send_initially(rst)
        else:
            self.log.warning("Received a message with code %s and type %s (those don't fit) from %s, ignoring it.", message.code, message.mtype, message.remote)

    def dispatch_error(self, error, remote):
        if self._active_exchanges is None:
            # Not entirely sure where it is so far; better just raise a warning
            # than an exception later, nothing terminally bad should come of
            # this error.
            self.log.warning("Internal shutdown sequence msismatch: error dispatched through messagemanager after shutown")
            return

        self.log.debug("Incoming error %s from %r", error, remote)

        # cancel requests first, and then exchanges: cancelling the pending
        # exchange would trigger enqueued requests to be transmitted
        self.token_manager.dispatch_error(error, remote)

        keys_for_removal = []
        for key, (messageerror_monitor, cancellable_timeout) in self._active_exchanges.items():
            (exchange_remote, message_id) = key
            if remote == exchange_remote:
                cancellable_timeout.cancel()
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
                    # not going via send_message because that would strip the
                    # mid and might do all other sorts of checks
                    self._send_initially(self._recent_messages[key])
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

    def _add_exchange(self, message, messageerror_monitor):
        """Add an "exchange" for outgoing CON message.

        CON (Confirmable) messages are automatically retransmitted by protocol
        until ACK or RST message with the same Message ID is received from
        target host."""

        key = (message.remote, message.mid)

        if message.remote not in self._backlogs:
            self._backlogs[message.remote] = []

        timeout = random.uniform(ACK_TIMEOUT, ACK_TIMEOUT * ACK_RANDOM_FACTOR)

        next_retransmission = self._schedule_retransmit(message, timeout, 0)
        self._active_exchanges[key] = (messageerror_monitor, next_retransmission)

        self.log.debug("Exchange added, message ID: %d.", message.mid)

    def _remove_exchange(self, message):
        """Remove exchange from active exchanges and cancel the timeout to next
        retransmission."""
        key = (message.remote, message.mid)

        if key not in self._active_exchanges:
            self.log.warning("Received %s from %s, but could not match it to a running exchange.", message.mtype, message.remote)
            return

        messageerror_monitor, next_retransmission = self._active_exchanges.pop(key)
        next_retransmission.cancel()
        if message.mtype is RST:
            messageerror_monitor()
        self.log.debug("Exchange removed, message ID: %d.", message.mid)

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
                next_message, messageerror_monitor = self._backlogs[remote].pop(0)
                self._send_initially(next_message, messageerror_monitor)
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

        messageerror_monitor, next_retransmission = self._active_exchanges.pop(key)
        # this should be a no-op, but let's be sure
        next_retransmission.cancel()

        if retransmission_counter < MAX_RETRANSMIT:
            self.log.info("Retransmission, Message ID: %d.", message.mid)
            self._send_via_transport(message)
            retransmission_counter += 1
            timeout *= 2

            next_retransmission = self._schedule_retransmit(message, timeout, retransmission_counter)
            self._active_exchanges[key] = (messageerror_monitor, next_retransmission)
        else:
            self.log.info("Exchange timed out trying to transmit %s", message)
            del self._backlogs[message.remote]
            self.token_manager.dispatch_error(error.ConRetransmitsExceeded("Retransmissions exceeded"), message.remote)

    #
    # coap dispatch, message-code sublayer: triggering custom actions based on incoming messages
    #

    def _process_ping(self, message):
        self.log.info('Received CoAP Ping from %s, replying with RST.', message.remote)
        rst = Message(mtype=RST, mid=message.mid, code=EMPTY, payload=b'')
        rst.remote = message.remote.as_response_address()
        # not going via send_message because that would strip the mid, and we
        # already know that it can go straight to the wire
        self._send_initially(rst)

    def _process_request(self, request):
        """Spawn a Responder for an incoming request, or feed a long-running
        responder if one exists."""

        if request.mtype == CON:
            def on_timeout(self, remote, token):
                mid, own_timeout = self._piggyback_opportunities.pop(
                        (remote, token))
                self._send_empty_ack(request.remote, mid,
                    "Response took too long to prepare")
            handle = self.loop.call_later(EMPTY_ACK_DELAY,
                    on_timeout, self, request.remote, request.token)
            key = (request.remote, request.token)
            if key in self._piggyback_opportunities:
                self.log.warning("New request came in while old request not"
                      " ACKed yet. Possible mismatch between EMPTY_ACK_DELAY"
                      " and EXCHANGE_LIFETIME. Cancelling ACK to ward off any"
                      " further confusion.")
                mid, old_handle = self._piggyback_opportunities.pop(key)
                old_handle.cancel()
            self._piggyback_opportunities[key] = (request.mid, handle)

        self.token_manager.process_request(request)

    def _process_response(self, response):
        """Feed a response back to whatever might expect it.

        Returns True if the response was expected (and should be ACK'd
        depending on mtype), and False if it was not expected (and should be
        RST'd)."""

        self.log.debug("Received Response: %r", response)

        return self.token_manager.process_response(response)

    #
    # outgoing messages
    #

    async def fill_or_recognize_remote(self, message):
        if message.remote is not None:
            if await self.message_interface.recognize_remote(message.remote):
                return True
        remote = await self.message_interface.determine_remote(message)
        if remote is not None:
            message.remote = remote
            return True
        return False

    def send_message(self, message, messageerror_monitor):
        """Encode and send message. This takes care of retransmissions (if
        CON), message IDs and rate limiting, but does not hook any events to
        responses. (Use the :class:`Request` class or responding resources
        instead; those are the typical callers of this function.)

        If notification about the progress of the exchange is required, an
        ExchangeMonitor can be passed in, which will receive the appropriate
        callbacks."""

        if message.mid is not None:
            # if you can give any reason why the application should provide a
            # fixed mid, lower the log level on demand and provide the reason
            # in a comment.
            self.log.warning("Message ID set on to-be-sent message, this is"
                  " probably unintended; clearing it.")
            message.mid = None

        if message.code.is_response():
            no_response = (message.opt.no_response or 0) & (1 << message.code.class_ - 1) != 0

            piggyback_key = (message.remote, message.token)
            if piggyback_key in self._piggyback_opportunities:
                mid, handle = self._piggyback_opportunities.pop(piggyback_key)
                handle.cancel()

                if no_response:
                    new_message = Message(code=EMPTY, mid=mid, mtype=ACK)
                    new_message.remote = message.remote.as_response_address()
                    message = new_message
                    self.log.debug("Turning to-be-sent message into an empty ACK due to no_response option.")
                else:
                    message.mtype = ACK
                    message.mid = mid
            else:
                if no_response:
                    self.log.debug("Stopping message in message manager as it is no_response and no ACK is pending.")
                    return

            message.opt.no_response = None

        if message.mtype is None:
            if self._active_exchanges is None:
                # during shutdown, this is all we can do
                message.mtype = NON
            else:
                if message.remote.is_multicast:
                    message.mtype = NON
                else:
                    # FIXME: on responses, this should take the request into
                    # consideration (cf. RFC7252 Section 5.2.3, answer to NON
                    # SHOULD be NON)
                    message.mtype = CON
        else:
            if self._active_exchanges is None:
                self.log.warning("Forcing message to be sent as NON even though specified because transport is shutting down")
                message.mtype = NON

        if message.mtype == CON and message.remote.is_multicast:
            raise ValueError("Refusing to send CON message to multicast address")

        if message.mid is None:
            message.mid = self._next_message_id()

        if message.mtype == CON and message.remote in self._backlogs:
            self.log.debug("Message to %s put into backlog", message.remote)
            self._backlogs[message.remote].append((message, messageerror_monitor))
        else:
            self._send_initially(message, messageerror_monitor)

    def _send_initially(self, message, messageerror_monitor=None):
        """Put the message on the wire for the first time, starting retransmission timeouts"""

        self.log.debug("Sending message %r", message)

        if message.mtype is CON:
            assert messageerror_monitor is not None, "messageerror_monitor needs to be set for CONs"
            self._add_exchange(message, messageerror_monitor)

        self._store_response_for_duplicates(message)

        self._send_via_transport(message)

    def _send_via_transport(self, message):
        """Put the message on the wire"""

        self.message_interface.send(message)

    def _next_message_id(self):
        """Reserve and return a new message ID."""
        message_id = self.message_id
        self.message_id = 0xFFFF & (1 + self.message_id)
        return message_id

    def _send_empty_ack(self, remote, mid, reason):
        """Send separate empty ACK for any reason.

        Currently, this can happen only once per Responder, that is, when the
        last block1 has been transferred and the first block2 is not ready
        yet."""

        self.log.debug("Sending empty ACK: %s", reason)
        ack = Message(
                mtype=ACK,
                code=EMPTY,
                payload=b"",
                )
        ack.remote = remote.as_response_address()
        ack.mid = mid
        # not going via send_message because that would strip the mid, and we
        # already know that it can go straight to the wire
        self._send_initially(ack)
