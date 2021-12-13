# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import functools
import random

from . import error
from . import interfaces
# To be used sparingly here: This deals with request / responses on the token
# layer. But the layer below won't even know that messages are responses, so it
# can't make the informed decisions we make here.
from .numbers.types import NON
from .pipe import Pipe

class TokenManager(interfaces.RequestInterface, interfaces.TokenManager):

    def __init__(self, context):
        self.context = context

        self._token = random.randint(0, 65535)
        self.outgoing_requests = {}
        """Unfinished outgoing requests (identified by token and remote)"""
        self.incoming_requests = {}
        """Unfinished incoming requests.

        ``(token, remote): (Pipe, stopper)`` where stopper is a
        function unregistes the Pipe event handler and thus
        indicates to the server the discontinued interest"""

        self.log = self.context.log
        self.loop = self.context.loop

        #self.token_interface = … -- needs to be set post-construction, because the token_interface in its constructor already needs to get its manager

    def __repr__(self):
        return '<%s for %s>' % (type(self).__name__, getattr(self, 'token_interface', '(unbound)'))

    @property
    def client_credentials(self):
        return self.context.client_credentials

    async def shutdown(self):
        while self.incoming_requests:
            key = next(iter(self.incoming_requests.keys()))
            (_, stop) = self.incoming_requests.pop(key)
            # This cancels them, not sending anything.
            #
            # FIXME should we? (RST? 5.00 Server Shutdown? An RST would only
            # work if we pushed this further down the shutdown chain; a 5.00 we
            # could raise in the task.)
            stop()
        self.incoming_requests = None

        while self.outgoing_requests:
            key = next(iter(self.outgoing_requests.keys()))
            request = self.outgoing_requests.pop(key)
            request.add_exception(error.LibraryShutdown())
        self.outgoing_requests = None

        await self.token_interface.shutdown()

    def next_token(self):
        """Reserve and return a new Token for request."""
        #TODO: add proper Token handling
        self._token = (self._token + 1) % (2 ** 64)
        return self._token.to_bytes(8, 'big').lstrip(b'\0')

    #
    # implement the tokenmanager interface
    #

    def dispatch_error(self, exception, remote):
        if self.outgoing_requests is None:
            # Not entirely sure where it is so far; better just raise a warning
            # than an exception later, nothing terminally bad should come of
            # this error.
            self.log.warning("Internal shutdown sequence msismatch: error dispatched through tokenmanager after shutown")
            return

        # NetworkError is what we promise users to raise from request etc; if
        # it's already a NetworkError and possibly more descriptive (eg. a
        # TimeoutError), we'll just let it through (and thus allow
        # differentiated handling eg. in application-level retries).
        if not isinstance(exception, error.NetworkError):
            cause = exception
            exception = error.NetworkError(str(exception))
            exception.__cause__ = cause

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
            (pipe, stop) = self.incoming_requests.pop(key)
            stop()

        pipe = Pipe(request, self.log)

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
                        # stop were called from its other possible caller,
                        # the start of process_request when a new request comes
                        # in on the same token)
                        stop,
                        )
            else:
                # It'd be tempting to raise here, but typically being called
                # from a task, it wouldn't propagate any further either, and at
                # least here we have a logger.
                self.log.error("Requests shouldn't receive errors at the level of a TokenManager any more, but this did: %s", ev)
            if not ev.is_last:
                return True
        def on_end():
            if key in self.incoming_requests:
                # It may not be, especially if it was popped in `(pipe, stop) = self.incoming_requests.pop(keyu)` above
                # FIXME Decide if one of them is sufficient
                del self.incoming_requests[key]
            # no further cleanup to do here: any piggybackable ack was already flushed
            # out by the first response, and if there was not even a
            # NoResponse, something went wrong above (and we can't tell easily
            # here).
        stop = pipe.on_event(on_event)
        pipe.on_interest_end(on_end)

        self.incoming_requests[key] = (pipe, stop)

        self.context.render_to_pipe(pipe)

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
