# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from .. import socknumbers

from asyncio import BaseProtocol
from asyncio.transports import BaseTransport

class RecvmsgDatagramProtocol(BaseProtocol):
    """Callback interface similar to asyncio.DatagramProtocol, but dealing with
    recvmsg data."""

    def datagram_msg_received(self, data, ancdata, flags, address):
        """Called when some datagram is received."""

    def datagram_errqueue_received(self, data, ancdata, flags, address):
        """Called when some data is received from the error queue"""

    def error_received(self, exc):
        """Called when a send or receive operation raises an OSError."""

def _set_result_unless_cancelled(fut, result):
    """Helper setting the result only if the future was not cancelled."""
    if fut.cancelled():
        return
    fut.set_result(result)

class RecvmsgSelectorDatagramTransport(BaseTransport):
    """A simple loop-independent transport that largely mimicks
    DatagramTransport but interfaces a RecvmsgSelectorDatagramProtocol.

    This does not implement any flow control, based on the assumption that it's
    not needed, for CoAP has its own flow control mechanisms."""

    max_size = 4096  # Buffer size passed to recvmsg() -- should suffice for a full MTU package and ample ancdata

    def __init__(self, loop, sock, protocol, waiter):
        super().__init__(extra={'socket': sock})
        self.__sock = sock
        # Persisted outside of sock because when GC breaks a reference cycle,
        # it can happen that the sock gets closed before this; we have to hope
        # that no new file gets opened and registered in the meantime.
        self.__sock_fileno = sock.fileno()
        self._loop = loop
        self._protocol = protocol

        loop.call_soon(protocol.connection_made, self)
        # only start reading when connection_made() has been called
        import weakref
        # We could add error handling in here like this:
        # ```
        # self = s()
        # if self is None or self.__sock is None:
        #     # The read event happened briefly before .close() was called,
        #     # but late enough that the caller of close did not yield to let
        #     # the event out; when remove_reader was then called, the
        #     # pending event was not removed, so it fires now that the
        #     # socket is already closed. (Depending on the GC's whims, self
        #     # may or may not have been GC'd, but if it wasn't yet, the
        #     # closed state is indicated by the lack of a __sock.
        #     #
        #     # Thus, silently (preferably with an ICMP error, but really
        #     # can't do that)...
        #     return
        # ```
        # That was done tentatively while debugging errors flying out of
        # _read_ready, but it turned out that this was not the actual error
        # source. Thus, I'm not adding the handler and assuming that close's
        # remove_reader is not racing against callbacks, and thus that s() is
        # always valid while the transport is around (and the weakref is really
        # only used to break up the reference cycles to ensure the GC is not
        # needed here).
        def rr(s=weakref.ref(self)):
            s()._read_ready()
        loop.call_soon(loop.add_reader, self.__sock_fileno, rr)
        loop.call_soon(_set_result_unless_cancelled, waiter, None)

    def close(self):
        if self.__sock is None:
            return

        if not self._loop.is_closed():
            self._loop.call_soon(self._protocol.connection_lost, None)

        self._loop.remove_reader(self.__sock_fileno)
        self.__sock.close()
        self.__sock = None
        self._protocol = None
        self._loop = None

    def __del__(self):
        if self.__sock is not None:
            self.close()

    def _read_ready(self):
        if socknumbers.HAS_RECVERR:
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
        try:
            self.__sock.sendmsg((data,), ancdata, flags, address)
            return
        except OSError as exc:
            self._protocol.error_received(exc)
            return
        except Exception as exc:
            self._fatal_error(exc,
                              'Fatal write error on datagram transport')
            return

async def create_recvmsg_datagram_endpoint(loop, factory, sock):
    """Create a datagram connection that uses recvmsg rather than recvfrom, and
    a RecvmsgDatagramProtocol protocol type.

    This is used like the create_datagram_endpoint method of an asyncio loop,
    but implemented in a generic way using the loop's add_reader method; thus,
    it's not a method of the loop but an independent function.

    Due to the way it is used in aiocoap, socket is not an optional argument
    here; it could be were this module ever split off into a standalone
    package.
    """
    sock.setblocking(False)

    protocol = factory()
    waiter = loop.create_future()
    transport = RecvmsgSelectorDatagramTransport(
            loop, sock, protocol, waiter)

    try:
        await waiter
    # see https://github.com/PyCQA/pycodestyle/issues/703
    except: # noqa: E722
        transport.close()
        raise

    return transport, protocol
