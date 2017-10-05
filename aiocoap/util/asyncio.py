# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Extensions to asyncio and workarounds around its shortcomings"""

from . import socknumbers

import asyncio

class PeekQueue:
    """Queue with a an asynchronous .peek() function.

    This is not implemented in terms of inheritance because it would depend on
    the implementation details of PriorityQueue.put(self, (1, item)) being
    itself implemented in terms of calling self.put_nowait."""

    def __init__(self, *args, **kwargs):
        self._inner = asyncio.PriorityQueue(*args, **kwargs)

    @asyncio.coroutine
    def put(self, item):
        yield from self._inner.put((1, item))

    def put_nowait(self, item):
        self._inner.put_nowait((1, item))

    @asyncio.coroutine
    def peek(self):
        oldprio, first = yield from self._inner.get()
        self._inner.put_nowait((0, first))
        return first

    @asyncio.coroutine
    def get(self):
        priority, first = yield from self._inner.get()
        return first

    def get_nowait(self):
        priority, first = self._inner.get_nowait()
        return first

import asyncio
try:
    from asyncio import StopAsyncIteration
except ImportError:
    class StopAsyncIteration(Exception):
        """Iteration stopper defined to make the asynchronous iterator
        interface usable on Python 3.4"""

class AsyncGenerator:
    """An object implementing the __aiter__ protocol until `async def / yield`
    can be used in all supported versions"""

    def __init__(self):
        self._queue = asyncio.Queue() #: (data, exception) tuples -- data is valid iff exception is None

    def __aiter__(self):
        return self

    @asyncio.coroutine
    def __anext__(self):
        data, exception = yield from self._queue.get()
        if exception is None:
            return data
        else:
            raise exception

    def throw(self, exception):
        self._queue.put_nowait((None, exception))

    def ayield(self, item):
        self._queue.put_nowait((item, None))

    def finish(self):
        self.throw(StopAsyncIteration)

from asyncio import DatagramProtocol
from asyncio.selector_events import _SelectorDatagramTransport, BaseSelectorEventLoop

class RecvmsgDatagramProtocol(DatagramProtocol):
    """Inheriting from this indicates that the instance expects to be called
    back datagram_msg_received instead of datagram_received"""

class RecvmsgSelectorDatagramTransport(_SelectorDatagramTransport):
    def __init__(self, *args, **kwargs):
        super(RecvmsgSelectorDatagramTransport, self).__init__(*args, **kwargs)

        self.__sock = self.get_extra_info('socket')
        if self.__sock is None:
            raise RuntimeError("RecvmsgSelectorDatagramTransport requires access to its underlying socket.")

    def _read_ready(self):
        try:
            data, ancdata, flags, addr = self.__sock.recvmsg(self.max_size, 1024, socknumbers.MSG_ERRQUEUE)
        except (BlockingIOError, InterruptedError):
            pass
        except OSError as exc:
            if repr(exc) == "OSError('received malformed or improperly truncated ancillary data',)":
                pass # workaround for https://bitbucket.org/pypy/pypy/issues/2649/recvmsg-with-empty-err-queue-raises-odd
            else:
                self._protocol.error_received(exc)
        except Exception as exc:
            self._fatal_error(exc, 'Fatal read error on datagram transport')
        else:
            self._protocol.datagram_errqueue_received(data, ancdata, flags, addr)

        # copied and modified from _SelectorDatagramTransport
        try:
            data, ancdata, flags, addr = self.__sock.recvmsg(self.max_size, 1024) # TODO: find a way for the application to tell the trensport how much data is expected
        except (BlockingIOError, InterruptedError):
            pass
        except OSError as exc:
            self._protocol.error_received(exc)
        except Exception as exc:
            self._fatal_error(exc, 'Fatal read error on datagram transport')
        else:
            self._protocol.datagram_msg_received(data, ancdata, flags, addr)

    def sendmsg(self, data, ancdata, flags, address):
        # copied and modified from _SelectorDatagramTransport.sendto
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError('data argument must be a bytes-like object, '
                            'not %r' % type(data).__name__)
        if not data:
            return

        if self._address and addr not in (None, self._address):
            raise ValueError('Invalid address: must be None or %s' %
                             (self._address,))

        if self._conn_lost and self._address:
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                logger.warning('socket.send() raised exception.')
            self._conn_lost += 1
            return

        if not self._buffer:
            # Attempt to send it right away first.
            try:
                self.__sock.sendmsg((data,), ancdata, flags, address)
                return
            except (BlockingIOError, InterruptedError):
                self._loop.add_writer(self.__sock.fileno(), self._sendto_ready)
            except OSError as exc:
                self._protocol.error_received(exc)
                return
            except Exception as exc:
                self._fatal_error(exc,
                                  'Fatal write error on datagram transport')
                return

        # Ensure that what we buffer is immutable.
        self._buffer.append((bytes(data), ancdata, flags, addr))
        self._maybe_pause_protocol()

    # TODO: not modified _sendto_ready as it's not used in this application and
    # would only be dead code -- given that we store 4-tuples instead of
    # 2-tuples, _sendto_ready will fail anyway cleanly

# monkey patching because otherwise we'd have to create a loop subclass and
# require this to be loaded.

_orig_mdt = BaseSelectorEventLoop._make_datagram_transport
def _new_mdt(self, sock, protocol, *args, **kwargs):
    if isinstance(protocol, RecvmsgDatagramProtocol):
        return RecvmsgSelectorDatagramTransport(self, sock, protocol, *args, **kwargs)
    else:
        return _orig_mdt(self, sock, protocol, *args, **kwargs)
BaseSelectorEventLoop._make_datagram_transport = _new_mdt
