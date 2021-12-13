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
import sys

from . import error
from .numbers import INTERNAL_SERVER_ERROR
from .util.asyncio import py38args

class Pipe:
    """Low-level meeting point between a request and a any responses that come
    back on it.

    A single request message is placed in the Pipe at creation time.
    Any responses, as well as any exception happening in the course of
    processing, are passed back to the requester along the Pipe. A
    response can carry an indication of whether it is final; an exception
    always is.

    This object is used both on the client side (where the Context on behalf of
    the application creates a Pipe and passes it to the network
    transports that send the request and fill in any responses) and on the
    server side (where the Context creates one for an incoming request and
    eventually lets the server implementation populate it with responses).

    This currently follows a callback dispatch style. (It may be developed into
    something where only awaiting a response drives the proces, though).

    Currently, the requester sets up the object, connects callbacks, and then
    passes the Pipe on to whatever creates the response.

    The creator of responses is notified by the Pipe of a loss of
    interest in a response when there are no more callback handlers registered
    by registering an on_interest_end callback. As the response callbacks need
    to be already in place when the Pipe is passed on to the
    responder, the absence event callbacks is signalled by callign the callback
    immediately on registration.

    To accurately model "loss of interest", it is important to use the
    two-phase setup of first registering actual callbacks and then producing
    events and/or placing on_interest_end callbacks; this is not clearly
    expressed in type or state yet. (One possibility would be for the
    Pipe to carry a preparation boolean, and which prohibits event
    sending during preparation and is_interest=True callback creation
    afterwards).

    This was previously named PlumbingRequest.

    **Stability**

    Sites and resources implemented by provinding a
    :meth:`~aiocoap.interfaces.Resource.render_to_pipe` method can stably use
    the :meth:`add_response` method of a Pipe (or something that quacks like
    it).

    They should not rely on :meth:`add_exception` but rather just raise the
    exception, and neither register :meth:`on_event` handlers (being the sole
    producer of events) nor hook to :meth:`on_interest_end` (instead, they can
    use finally clauses or async context managers to handle any cleanup when
    the cancellation of the render task indicates the peer's loss of interest).
    """

    Event = namedtuple("Event", ("message", "exception", "is_last"))

    # called by the initiator of the request

    def __init__(self, request, log):
        self.request = request
        self.log = log

        self._event_callbacks = []
        """list[(callback, is_interest)], or None during event processing, or
        False when there were no more event callbacks and an the
        on_interest_end callbacks have already been called"""

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

        for (cb, is_interest) in self._event_callbacks[:]:
            keep_calling = cb(event)
            if not keep_calling:
                if self._event_callbacks is False:
                    # All interest was just lost during the callback
                    return

                self._event_callbacks.remove((cb, is_interest))

        if not self._any_interest():
            self._end()

    def add_response(self, response, is_last=False):
        self._add_event(self.Event(response, None, is_last))

    def add_exception(self, exception):
        self._add_event(self.Event(None, exception, True))

def run_driving_pipe(pipe, coroutine, name=None):
    """Create a task from a coroutine where the end of the coroutine produces a
    terminal event on the pipe, and lack of interest in the pipe cancels the
    task.

    The coroutine will typically produce output into the pipe; that
    connection is set up by the caller like as in
    ``run_driving_pipe(pipe, render_to(pipe))``.

    The create task is not returned, as the only sensible operation on it would
    be cancellation and that's already set up from the pipe.
    """

    async def wrapped():
        try:
            await coroutine
        except Exception as e:
            pipe.add_exception(e)
        # Not doing anything special about cancellation: it indicates the
        # peer's loss of interest, so there's no use in sending anythign out to
        # someone not listening any more
        #
        # (We'd *like* to do something on the Python 3.7 versions whose
        # cancelled threads show errors, but there we can't stop it in here
        # because catching the CancelledError doesn't remove the taint from the
        # task).

    task = asyncio.create_task(
            wrapped(),
            **py38args(name=name),
            )
    if sys.version_info < (3, 8):
        # These Python versions used to complain about cancelled tasks, where
        # really a cancelled task is perfectly natural (especially here where
        # it's just not needed any more because nobody is listening to what it
        # produces). As catching CancellationError doesn't help silencing them,
        # this workaround ensures the cancellations don't raise.
        def silence_cancellation(task):
            try:
                task.result()
            except asyncio.CancelledError:
                pass
        task.add_done_callback(silence_cancellation)
    pipe.on_interest_end(task.cancel)

def error_to_message(old_pr, log):
    """Given a pipe set up by the requester, create a new pipe to pass on to a
    responder.

    Any exceptions produced by the responder will be turned into terminal
    responses on the original pipe, and loss of interest is forwarded."""

    from .message import Message

    next_pr = Pipe(old_pr.request, log)

    def on_event(event):
        if event.message is not None:
            old_pr.add_response(event.message, event.is_last)
            return not event.is_last

        e = event.exception

        if isinstance(e, error.RenderableError):
            # the repr() here is quite imporant for garbage collection
            log.info("Render request raised a renderable error (%s), responding accordingly.", repr(e))
            try:
                msg = e.to_message()
                if msg is None:
                    # This deserves a separate check because the ABC checks
                    # that should ensure that the default to_message method is
                    # never used in concrete classes fails due to the metaclass
                    # conflict between ABC and Exceptions
                    raise ValueError("Exception to_message failed to produce a message on %r" % e)
            except Exception as e2:
                log.error("Rendering the renderable exception failed: %r", e2, exc_info=e2)
                msg = Message(code=INTERNAL_SERVER_ERROR)
            old_pr.add_response(msg, is_last=True)
        else:
            log.error("An exception occurred while rendering a resource: %r", e, exc_info=e)
            old_pr.add_response(Message(code=INTERNAL_SERVER_ERROR), is_last=True)

        return False

    remove_interest = next_pr.on_event(on_event)
    old_pr.on_interest_end(remove_interest)
    return next_pr

class IterablePipe:
    """A stand-in for a Pipe that the requesting party can use
    instead. It should behave just like a Pipe to the responding
    party, but the caller does not register on_event handlers and instead
    iterates asynchronously over the events.

    Note that the PR can be aitered over only once, and does not support any
    additional hook settings once asynchronous iteration is started; this is
    consistent with the usage pattern of pipes.
    """

    def __init__(self, request):
        self.request = request

        self.__on_interest_end = []

        # FIXME: This is unbounded -- pipes should gain support for
        # backpressure.
        self.__queue = asyncio.Queue()

    def on_interest_end(self, callback):
        try:
            self.__on_interest_end.append(callback)
        except AttributeError:
            raise RuntimeError("Attempted to declare interest in the end of a IterablePipe on which iteration already started") from None

    def __aiter__(self):
        i = self.Iterator(self.__queue, self.__on_interest_end)
        del self.__on_interest_end
        return i

    def _add_event(self, e):
        self.__queue.put_nowait(e)

    def add_response(self, response, is_last=False):
        self._add_event(Pipe.Event(response, None, is_last))

    def add_exception(self, exception):
        self._add_event(Pipe.Event(None, exception, True))

    class Iterator:
        def __init__(self, queue, on_interest_end):
            self.__queue = queue
            self.__on_interest_end = on_interest_end

        async def __anext__(self):
            return await self.__queue.get()

        def __del__(self):
            # This is pretty reliable as the iterator is only created and
            # referenced in the desugaring of the `async for`.
            for c in self.__on_interest_end:
                c()
