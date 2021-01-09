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
import os
import random

from . import error
from . import interfaces
# To be used sparingly here: This deals with request / responses on the token
# layer. But the layer below won't even know that messages are responses, so it
# can't make the informed decisions we make here.
from .numbers.types import NON

class TokenManager(interfaces.RequestInterface, interfaces.TokenManager):
    def __init__(self, context):
        self.context = context

        self._token = random.randint(0, 65535)
        self.outgoing_requests = {}  #: Unfinished outgoing requests (identified by token and remote)
        self.incoming_requests = {}  #: Unfinished incoming requests.
                                     #: ``(token, remote): (PlumbingRequest, stopper)``
                                     #: where stopper is a function unregistes
                                     #: the PlumbingRequest event handler and
                                     #: thus indicates to the server the
                                     #: discontinued interest

        self.log = self.context.log
        self.loop = self.context.loop

        #self.token_interface = … -- needs to be set post-construction, because the token_interface in its constructor already needs to get its manager

    @property
    def client_credentials(self):
        return self.context.client_credentials

    async def shutdown(self):
        while self.outgoing_requests:
            key = next(iter(self.outgoing_requests.keys()))
            request = self.outgoing_requests.pop(key)
            request.add_exception(error.LibraryShutdown())
        self.outgoing_requests = None

        # No handling of self.incoming_requests necssary -- or should we send a
        # request.add_response(... RST? 5.00 Server Shutdown?) to them?

        await self.token_interface.shutdown()

    def next_token(self):
        """Reserve and return a new Token for request."""
        #TODO: add proper Token handling
        self._token = (self._token + 1) % (2 ** 64)
        return self._token.to_bytes(8, 'big').lstrip(b'\0')

    #
    # implement the tokenmanager interface
    #

    def dispatch_error(self, errno, remote):
        keys_for_removal = []
        # dispatch_error may want to migrate to passing around actual exceptions
        original_error = OSError(errno, "no details" if errno is None else os.strerror(errno))
        exception = error.NetworkError(str(original_error))
        exception.__cause__ = original_error

        # The stopping calls would pop items from the pending requests --
        # iterating once, extracting the stoppers and then calling them en
        # batch
        stoppers = []
        for key, request in self.outgoing_requests.items():
            (token, request_remote) = key
            if request_remote == remote:
                stoppers.append(lambda request=request, exception=exception: request.add_exception(exception))

        for ((_, _r), (_, stopper)) in self.incoming_requests.items():
            if remote == _r:
                stoppers.append(stopper)
        for stopper in stoppers:
            stopper()

    def process_request(self, request):
        key = (request.token, request.remote)

        if key in self.incoming_requests:
            # This is either a "I consider that token invalid, probably forgot
            # about it, but here's a new request" or renewed interest in an
            # observation, which gets modelled as a new request at thislevel
            self.log.debug("Incoming request overrides existing request")
            # Popping: FIXME Decide if one of them is sufficient (see `del self.incoming_requests[key]` below)
            (pr, pr_stop) = self.incoming_requests.pop(key)
            pr_stop()

        pr = PlumbingRequest(request, self.log)

        # FIXME: what can we pass down to the token_interface?  certainly not
        # the request, but maybe the request with a response filter applied?
        def on_event(ev):
            if ev.message is not None:
                m = ev.message
                # FIXME: should this code warn if token or remote are set?
                m.token = request.token
                m.remote = request.remote.as_response_address()

                if m.mtype is None and request.mtype is NON:
                    # Default to sending NON to NON requests; rely on the
                    # default (CON if stand-alone else ACK) otherwise.
                    m.mtype = NON
                self.token_interface.send_message(
                        m,
                        # No more interest from *that* remote; as it's the only
                        # thing keeping the PR alive, it'll go its course of
                        # vanishing for lack of interest (as it would if
                        # pr_stop were called from its other possible caller,
                        # the start of process_request when a new request comes
                        # in on the same token)
                        pr_stop,
                        )
            else:
                self.log.error("Requests shouldn't receive errors at the level of a TokenManager any more, but this did: %s", ev)
            if not ev.is_last:
                return True
        def on_end():
            if key in self.incoming_requests:
                # It may not be, especially if it was popped in `(pr, pr_stop) = self.incoming_requests.pop(keyu)` above
                # FIXME Decide if one of them is sufficient
                del self.incoming_requests[key]
            # no further cleanup to do here: any piggybackable ack was already flushed
            # out by the first response, and if there was not even a
            # NoResponse, something went wrong above (and we can't tell easily
            # here).
        pr_stop = pr.on_event(on_event)
        pr.on_interest_end(on_end)

        self.incoming_requests[key] = (pr, pr_stop)

        self.context.render_to_plumbing_request(pr)

    def process_response(self, response):
        key = (response.token, response.remote)
        if key not in self.outgoing_requests:
            # maybe it was a multicast...
            key = (response.token, None)

        try:
            request = self.outgoing_requests[key]
        except KeyError:
            self.log.info("Response %r could not be matched to any request", response)
            return False
        else:
            self.log.debug("Response %r matched to request %r", response, request)

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

        if final:
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

        self.log.debug("Sending request - Token: %s, Remote: %s", msg.token.hex(), msg.remote)

        try:
            send_canceller = self.token_interface.send_message(msg, lambda: request.add_exception(error.MessageError))
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
            request.on_event(lambda ev: (send_canceller(), False)[1],
                    is_interest=False)

        # A request sent over the multicast interface will only return a single
        # response and otherwise behave quite like an anycast request (which is
        # probably intended).
        if msg.remote.is_multicast:
            self.log.warning("Sending request to multicast via unicast request method")
            key = (msg.token, None)
        else:
            key = (msg.token, msg.remote)
        self.outgoing_requests[key] = request
        request.on_interest_end(functools.partial(self.outgoing_requests.pop, key, None))

'''
    def multicast_request(self, request):
        return MulticastRequest(self, request).responses
'''


class PlumbingRequest:
    """Low-level meeting point between a request and a any responses that come
    back on it.

    A single request message is placed in the PlumbingRequest at creation time.
    Any responses, as well as any exception happening in the course of
    processing, are passed back to the requester along the PlumbingRequest. A
    response can carry an indication of whether it is final; an exception
    always is.

    This object is used both on the client side (where the Context on behalf of
    the application creates a PlumbingRequest and passes it to the network
    transports that send the request and fill in any responses) and on the
    server side (where the Context creates one for an incoming request and
    eventually lets the server implementation populate it with responses).

    This currently follows a callback dispatch style. (It may be developed into
    something where only awaiting a response drives the proces, though).

    Currently, the requester sets up the object, connects callbacks, and then
    passes the PlumbingRequest on to whatever creates the response.

    The creator of responses is notified by the PlumbingRequest of a loss of
    interest in a response when there are no more callback handlers registered
    by registering an on_interest_end callback. As the response callbacks need
    to be already in place when the PlumbingRequest is passed on to the
    responder, the absence event callbacks is signalled by callign the callback
    immediately on registration.

    To accurately model "loss of interest", it is important to use the
    two-phase setup of first registering actual callbacks and then producing
    events and/or placing on_interest_end callbacks; this is not clearly
    expressed in type or state yet. (One possibility would be for the
    PlumbingRequest to carry a preparation boolean, and which prohibits event
    sending during preparation and is_interest=True callback creation
    afterwards)."""

    Event = namedtuple("Event", ("message", "exception", "is_last"))

    # called by the initiator of the request

    def __init__(self, request, log):
        self.request = request
        self.log = log

        self._event_callbacks = [] # list[(callback, is_interest)],
                                   # or None during event processing,
                                   # or False when there were no more event
                                   # callbacks and an the on_interest_end
                                   # callbacks have already been called

    def __repr__(self):
        return '<%s at %#x around %r with %r callbacks>'%(type(self).__name__, id(self), self.request, len(self._event_callbacks) if self._event_callbacks else self._event_callbacks)

    def _any_interest(self):
        return any(is_interest for (cb, is_interest) in self._event_callbacks)

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

    def on_event(self, callback, is_interest=True):
        """Call callback on any event. The callback must return True to be
        called again after an event. Callbacks must not produce new events or
        deregister unrelated event handlers.

        If is_interest=False, the callback will not be counted toward the
        active callbacks, and will receive a (None, None, is_last=True) event
        eventually.

        To unregister the handler, call the returned closure; this can trigger
        on_interest_end callbacks.
        """
        self._event_callbacks.append((callback, is_interest))
        return functools.partial(self._unregister_on_event, callback)

    def _unregister_on_event(self, callback):
        if self._event_callbacks is False:
            # They wouldn't be called any more so they're already dropped.a
            # It's OK that the caller cleans up after itself: Sure it could
            # register an on_interest_end, but that's really not warranted if
            # all it wants to know is whether it'll have to execute cleanup
            # when it's shutting down or not.
            return

        self._event_callbacks = [(cb, i) for (cb, i) in self._event_callbacks if callback is not cb]
        if not self._any_interest():
            self._end()

    def on_interest_end(self, callback):
        """Register a callback that will be called exactly once -- either right
        now if there is not even a current indicated interest, or at a last
        event, or when no more interests are present"""

        if self._event_callbacks is False:
            # Happens, for example, when a proxy receives multiple requests on a single token
            self.log.warning("on_interest_end callback %r added after %r has already ended", callback, self)
            callback()
            return

        if self._any_interest():
            self._event_callbacks.append((
                lambda e: ((callback(), False) if e.is_last else (None, True))[1],
                False
                ))
        else:
            callback()

    def _end(self):
        cbs = self._event_callbacks
        self._event_callbacks = False
        tombstone = self.Event(None, None, True)
        [cb(tombstone) for (cb, _) in cbs]

    # called by the responding side

    def _add_event(self, event):
        if self._event_callbacks is False:
            # Happens, for example, when a proxy receives multiple requests on a single token
            self.log.warning("Response %r added after %r has already ended", event, self)
            return

        cbs = self._event_callbacks
        # Force an error when during event handling an event is generated
        self._event_callbacks = None
        surviving = [(cb, is_interest) for (cb, is_interest) in cbs if cb(event)]

        self._event_callbacks = surviving

        if not self._any_interest():
            self._end()

    def add_response(self, response, is_last=False):
        self._add_event(self.Event(response, None, is_last))

    def add_exception(self, exception):
        self._add_event(self.Event(None, exception, True))
