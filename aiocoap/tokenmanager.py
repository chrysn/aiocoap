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

class TokenManager(interfaces.RequestInterface, interfaces.TokenManager):
    def __init__(self, context):
        self.context = context

        self._token = random.randint(0, 65535)
        self.outgoing_requests = {}  #: Unfinished outgoing requests (identified by token and remote)
        self.incoming_requests = {}  #: Unfinished incoming requests. ``(path-tuple, remote): (Request, "run" task)``

        self.log = self.context.log
        self.loop = self.context.loop

        #self.token_interface = … -- needs to be set post-construction, because the token_interface in its constructor already needs to get its manager

    @property
    def client_credentials(self):
        return self.context.client_credentials

    async def shutdown(self):
        for request in self.outgoing_requests.values():
            request.add_exception(error.LibraryShutdown())
        self.outgoing_requests = None

        for request, task in self.incoming_requests.values():
            # FIXME decide what to do with pending requests
            # request.add_response(... RST? 5.00 Server Shutdown?
            task.cancel()

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
        self._token = (self._token + 1) % (2 ** 64)
        return self._token.to_bytes(8, 'big').lstrip(b'\0')

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
            self.outgoing_requests.pop(k)

        keys_for_removal = [
                (_p, _r)
                for (_p, _r)
                in self.incoming_requests
                if _r == remote
                ]
        for key in keys_for_removal:
            pr, task = self.incoming_requests.pop(key)
            pr.stop_interest()
            task.cancel()

    def process_request(self, request):
        key = (request.token, request.remote)

        if key in self.incoming_requests:
            # This is either a "I consider that token invalid, probably forgot
            # about it, but here's a new request" or renewed interest in an
            # observation, which gets modelled as a new request at thislevel
            self.log.debug("Incoming request overrides existing request")
            pr, task = self.incoming_requests.pop(key)
            pr.stop_interest()
            task.cancel()

        pr = PlumbingRequest(request)

        # FIXME: what can we pass down to the token_interface?  certainly not
        # the request, but maybe the request with a response filter applied?
        #
        # for now, starting a task just to serice the queues, add a token and
        # push on the messages -- should be more callback-driven at this level,
        # though.
        async def run():
            while True:
                ev = await pr._events.get()
                if ev.message is not None:
                    m = ev.message
                    # FIXME: should this code warn if token or remote are set?
                    m.token = request.token
                    m.remote = request.remote.as_response_address()
                    self.token_interface.send_message(m)
                else:
                    self.log.error("Requests shouldn't receive errors at the level of a TokenManager any more, but this did: %s", ev.exception)
                if ev.is_last:
                    break
            # no cleanup to do here: any piggybackable ack was already flushed
            # out by the first response, and if there was not even a
            # NoResponse, something went wrong above (and we can't tell easily
            # here).
        task = self.loop.create_task(run())

        self.incoming_requests[key] = (pr, task)

        self.context.render_to_plumbing_request(pr)

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
    # it is expected that this will change into something that's more a
    # callback dispatcher and less something that's keeping buffered state;
    # leaving it as it is for now until it can be more comfortably be
    # refactored when the test suite can be run again

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
