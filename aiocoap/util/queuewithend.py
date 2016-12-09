"""This is a relic from before the ``__aiter__`` protocol was established; it
will be phased out before aiocoap 1.0 is released."""

import abc
import enum
import asyncio

class AsyncIterable(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    @asyncio.coroutine
    def can_peek(self):
        """Return True when a result is ready to be fetched with .get_nowait(),
        and False when no more items can be fetched."""

    @abc.abstractmethod
    @asyncio.coroutine
    def get_nowait(self):
        """Fetch the next item. This must only be called once after can_peek
        has returned True."""

class QueueWithEnd(AsyncIterable):
    """A QueueWithEnd shares a Queue's behavior in that it gets fed with put
    and consumed with get_nowait. Contrary to a Queue, this is designed to be
    consumed only by one entity, which uses the coroutine can_peek to make sure
    the get_nowait will succeed.

    Another difference between a Queue and a QueueWithEnd is that the latter
    can also terminate (which is indicated by can_peek returning False and set
    by the finish coroutine) and raise exceptions (which raise from the
    get_nowait function and are set by the put_exception coroutine).
    """
    Type = enum.Enum("QueueWithEnd.Type", "notpeeked value end exception")

    def __init__(self, maxsize=0):
        # (type, value)
        self._queue = asyncio.Queue(maxsize)
        self._ended = False
        self._flag = self.Type.notpeeked

    def __repr__(self):
        return "<%s %#x flag %s%s>" % (type(self).__name__, id(self), self._flag, " (%s)" %
                self._value if self._flag in (self.Type.value,
                    self.Type.exception) else "")

    # AsyncIterable interface

    @asyncio.coroutine
    def can_peek(self):
        if self._flag is not self.Type.notpeeked:
            return True
        self._flag, self._value = yield from self._queue.get()
        return self._flag is not self.Type.end

    def get_nowait(self):
        if self._flag in (self.Type.notpeeked, self.Type.end):
            raise asyncio.QueueEmpty()
        elif self._flag is self.Type.exception:
            raise self._value
        else:
            self._flag = self.Type.notpeeked
            return self._value

    # feeder interface

    @asyncio.coroutine
    def put(self, value):
        yield from self._put(self.Type.value, value)

    @asyncio.coroutine
    def put_exception(self, value):
        yield from self._put(self.Type.exception, value)
        self._ended = True

    @asyncio.coroutine
    def finish(self):
        yield from self._put(self.Type.end, None)
        self._ended = True

    @asyncio.coroutine
    def _put(self, type, value):
        if self._ended:
            raise asyncio.InvalidStateError("%s has already ended"%type(self).__name__)
        yield from self._queue.put((type, value))

    # a simple way to create a feeder with something like an explicit yield

    @classmethod
    def cogenerator(cls, maxsize=0):
        """Coroutine decorator that passes a callable `asyncyield` into the function
        as the first argument and returns a QueueWithEnd. It is implicitly
        finished when the coroutine returns.

        >>> @QueueWithEnd.cogenerator()
        >>> def count_slowly(asyncyield, count_to=count_to):
        ...     for i in range(count_to):
        ...         yield from asyncio.sleep(1)
        ...         yield from asyncyield(i + 1)
        >>> counter = count_slowly(10)
        >>> while (yield from counter.can_peek()):
        ...     i = counter.get_nowait()
        ...     print("Current count is %d"%i)
        """

        def decorate(function):
            cofun = asyncio.coroutine(function)
            def wrapped(*args, **kwargs):
                result = cls(maxsize=maxsize)
                def guarding():
                    running = cofun(result.put, *args, **kwargs)
                    try:
                        yield from running
                    except Exception as e:
                        yield from result.put_exception(e)
                    else:
                        yield from result.finish()
                asyncio.Task(guarding())
                return result
            return wrapped
        return decorate

    @classmethod
    def merge(cls, queues):
        """Asyncio's `as_completed` does not work with QueueWithEnd objects for
        the same reason it can't replace it (missing end-of-loop indication);
        the `merge` classmethod can be used instead to fetch results
        indiscriminately from queues as they are completed:

        >>> @QueueWithEnd.cogenerator()
        >>> def count(asyncyield):
        ...     for i in range(3):
        ...         yield from asyncyield(i + 1)
        ...         yield from time.sleep(0.1 * i)
        >>> firstcount = count()
        >>> secondcount = count()
        >>> merged = QueueWithEnd.merged([firstcount, secondcount])
        >>> while (yield from merged.can_peek()):
        ...     print(merged.get_nowait())
        1
        2
        1
        2
        3
        3
        """
        merged = cls(maxsize=1)
        merged.subqueues = queues[:]

        @asyncio.coroutine
        def feeder(queue, merged):
            while (yield from queue.can_peek()):
                if queue._flag == cls.Type.end:
                    merged.subqueues.remove(queue)
                    if not merged.subqueues:
                        merged.finish()
                        return
                yield from merged._put(queue._flag, queue._value)
                queue._flag = cls.Type.notpeeked
        for s in merged.subqueues:
            asyncio.Task(feeder(s, merged))

        return merged

    # implementing the Future interface -- note that it's neither a Future by
    # inheritance, nor does it offer the complete Future interface; but it can
    # be used in `for value in (yield from ...):`

    def __iter__(self):
        result = []
        while (yield from self.can_peek()):
            result.append(self.get_nowait())
        return result

    # compatibility to the original `Its` class

    more = can_peek
    value = property(get_nowait)
    # another old name
    consume = get_nowait
