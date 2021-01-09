# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a MessageInterface that handles coaps:// using a
wrapped tinydtls library.

This currently only implements the client side. To have a test server, run::

    $ git clone https://github.com/obgm/libcoap.git --recursive
    $ cd libcoap
    $ ./autogen.sh
    $ ./configure --with-tinydtls --disable-shared --disable-documentation
    $ make
    $ ./examples/coap-server -k secretPSK

(Using TinyDTLS in libcoap is important; with the default OpenSSL build, I've
seen DTLS1.0 responses to DTLS1.3 requests, which are hard to debug.)

The test server with its built-in credentials can then be accessed using::

    $ echo '{"coaps://localhost/*": {"dtls": {"psk": {"ascii": "secretPSK"}, "client-identity": {"ascii": "client_Identity"}}}}' > testserver.json
    $ ./aiocoap-client coaps://localhost --credentials testserver.json

While it is planned to allow more programmatical construction of the
credentials store, the currently recommended way of storing DTLS credentials is
to load a structured data object into the client_credentials store of the context:

>>> c = await aiocoap.Context.create_client_context()          # doctest: +SKIP
>>> c.client_credentials.load_from_dict(
...     {'coaps://localhost/*': {'dtls': {
...         'psk': b'secretPSK',
...         'client-identity': b'client_Identity',
...         }}})                                               # doctest: +SKIP

where, compared to the JSON example above, byte strings can be used directly
rather than expressing them as 'ascii'/'hex' (`{'hex': '30383135'}` style works
as well) to work around JSON's limitation of not having raw binary strings.

Bear in mind that the aiocoap CoAPS support is highly experimental; for
example, while requests to this server do complete, error messages are still
shown during client shutdown.
"""

import asyncio
import weakref
import functools
import time
import warnings

from ..util import hostportjoin, hostportsplit
from ..message import Message
from .. import interfaces, error
from ..numbers import COAPS_PORT
from ..credentials import CredentialsMissingError

# tinyDTLS passes address information around in its session data, but the way
# it's used here that will be ignored; this is the data that is sent to / read
# from the tinyDTLS functions
_SENTINEL_ADDRESS = "::1"
_SENTINEL_PORT = 1234

DTLS_EVENT_CONNECT = 0x01DC
DTLS_EVENT_CONNECTED = 0x01DE
DTLS_EVENT_RENEGOTIATE = 0x01DF

LEVEL_NOALERT = 0 # seems only to be issued by tinydtls-internal events

# from RFC 5246
LEVEL_WARNING = 1
LEVEL_FATAL = 2
CODE_CLOSE_NOTIFY = 0

# tinydtls can not be debugged in the Python way; if you need to get more
# information out of it, use the following line:
#dtls.setLogLevel(0xff)

# FIXME this should be exposed by the dtls wrapper
DTLS_TICKS_PER_SECOND = 1000
DTLS_CLOCK_OFFSET = time.time()

# If dispatch_error is rewritten to handle exceptions rather than OS error
# codes, these may need to inherit from suitable aiocoap.error bases because
# they can be passed out then (so far, they only show up in log messages)
class CloseNotifyReceived(Exception):
    """The DTLS connection a request was sent on raised was closed by the
    server while the request was being processed"""

class FatalDTLSError(Exception):
    """The DTLS connection a request was sent on raised a fatal error while the
    request was being processed"""

class DTLSClientConnection(interfaces.EndpointAddress):
    # FIXME not only does this not do error handling, it seems not to even
    # survive its 2**16th message exchange.

    is_multicast = False
    is_multicast_locally = False
    hostinfo = None # stored at initualization time
    uri_base = property(lambda self: 'coaps://' + self.hostinfo)
    # Not necessarily very usable given we don't implement responding to server
    # connection, but valid anyway
    uri_base_local = property(lambda self: 'coaps://' + self.hostinfo_local)
    scheme = 'coaps'

    @property
    def hostinfo_local(self):
        # See TCP's.hostinfo_local
        host, port, *_ = self._transport.get_extra_info('socket').getsockname()
        if port == COAPS_PORT:
            port = None
        return hostportjoin(host, port)

    def __init__(self, host, port, pskId, psk, coaptransport):
        self._ready = False
        self._queue = [] # stores sent packages while connection is being built

        self._host = host
        self._port = port
        self._pskId = pskId
        self._psk = psk
        self.coaptransport = coaptransport
        self.hostinfo = hostportjoin(host, None if port == COAPS_PORT else port)

        self._startup = asyncio.ensure_future(self._start())

    def _remove_from_pool(self):
        """Remove self from the MessageInterfaceTinyDTLS's pool, so that it
        will not be used in new requests.

        This is idempotent (to allow quick removal and still remove it in a
        finally clause) and not thread safe.
        """
        poolkey = (self._host, self._port, self._pskId)
        if self.coaptransport._pool.get(poolkey) is self:
            del self.coaptransport._pool[poolkey]

    def send(self, message):
        if self._queue is not None:
            self._queue.append(message)
        else:
            # most of the time that will have returned long ago
            self._retransmission_task.cancel()

            self._dtls_socket.write(self._connection, message)

            self._retransmission_task = asyncio.Task(self._run_retransmissions())

    log = property(lambda self: self.coaptransport.log)

    def _build_accessor(self, method):
        """Think self._build_accessor('_write')() == self._write(), just that
        it's returning a weak wrapper that allows refcounting-based GC to
        happen when the remote falls out of use"""
        weakself = weakref.ref(self)
        def wrapper(*args, __weakself=weakself, __method=method):
            self = __weakself()
            if self is None:
                warnings.warn("DTLS module did not shut down the DTLSSocket "
                        "perfectly; it still tried to call %s in vain" %
                        __method)
                return
            return getattr(self, __method)(*args)
        wrapper.__name__ = "_build_accessor(%s)" % method
        return wrapper

    async def _start(self):
        from DTLSSocket import dtls

        self._dtls_socket = None

        self._connection = None

        try:
            self._transport, _ = await self.coaptransport.loop.create_datagram_endpoint(
                    self.SingleConnection.factory(self),
                    remote_addr=(self._host, self._port),
                    )

            self._dtls_socket = dtls.DTLS(
                    read=self._build_accessor("_read"),
                    write=self._build_accessor("_write"),
                    event=self._build_accessor("_event"),
                    pskId=self._pskId,
                    pskStore={self._pskId: self._psk},
                    )
            self._connection = self._dtls_socket.connect(_SENTINEL_ADDRESS, _SENTINEL_PORT)

            self._retransmission_task = asyncio.Task(self._run_retransmissions())

            self._connecting = asyncio.Future()
            await self._connecting

            queue = self._queue
            self._queue = None

            for message in queue:
                # could be a tad more efficient by stopping the retransmissions
                # in a go, then doing just the punch line and then starting it,
                # but practically this will be a single thing most of the time
                # anyway
                self.send(message)

            return

        except OSError as e:
            self.log.debug("Expressing exception %r as errno %d.", e, e.errno)
            self.coaptransport.ctx.dispatch_error(e.errno, self)
        except asyncio.CancelledError:
            # Can be removed starting with Python 3.8 as it's a workaround for
            # https://bugs.python.org/issue32528
            raise
        except Exception as e:
            self.log.error("Exception %r can not be represented as errno, setting -1.", e)
            self.coaptransport.ctx.dispatch_error(-1, self)
        finally:
            if self._queue is None:
                # all worked, we're done here
                return

            self.shutdown()

    async def _run_retransmissions(self):
        while True:
            when = self._dtls_socket.checkRetransmit() / DTLS_TICKS_PER_SECOND
            if when == 0:
                return
            now = time.time() - DTLS_CLOCK_OFFSET
            await asyncio.sleep(when - now)


    def shutdown(self):
        self._remove_from_pool()

        self._startup.cancel()
        self._retransmission_task.cancel()

        if self._connection is not None:
            try:
                self._dtls_socket.close(self._connection)
            except:
                pass # _dtls_socket actually does raise an empty Exception() here
        # doing this here allows the dtls socket to send a final word, but
        # by closing this, we protect the nascent next connection from any
        # delayed ICMP errors that might still wind up in the old socket
        self._transport.close()

    def __del__(self):
        # Breaking the loops between the DTLS object and this here to allow for
        # an orderly Alet (fatal, close notify) to go out -- and also because
        # DTLSSocket throws `TypeError: 'NoneType' object is not subscriptable`
        # from its destructor while the cyclical dependency is taken down.
        self.shutdown()

    def _inject_error(self, e):
        """Put an error to all pending operations on this remote, just as if it
        were raised inside the main loop."""

        if isinstance(e, OSError):
            self.log.debug("Expressing exception %r as errno %d.", e, e.errno)
            self.coaptransport.ctx.dispatch_error(e.errno, self)
        else:
            self.log.error("Exception %r can not be represented as errno, setting -1.", e)
            self.coaptransport.ctx.dispatch_error(-1, self)

        self.shutdown()

    # dtls callbacks

    def _read(self, sender, data):
        # ignoring sender: it's only _SENTINEL_*

        try:
            message = Message.decode(data, self)
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s", sender)
            return len(data)

        self.coaptransport.ctx.dispatch_message(message)

        return len(data)

    def _write(self, recipient, data):
        # ignoring recipient: it's only _SENTINEL_*
        try:
            t = self._transport
        except:
            # tinydtls sends callbacks very very late during shutdown (ie.
            # `hasattr` and `AttributeError` are all not available any more,
            # and even if the DTLSClientConnection class had a ._transport, it
            # would already be gone), and it seems even a __del__ doesn't help
            # break things up into the proper sequence.
            return 0
        t.sendto(data)
        return len(data)

    def _event(self, level, code):
        if (level, code) == (LEVEL_NOALERT, DTLS_EVENT_CONNECT):
            return
        elif (level, code) == (LEVEL_NOALERT, DTLS_EVENT_CONNECTED):
            self._connecting.set_result(True)
        elif (level, code) == (LEVEL_FATAL, CODE_CLOSE_NOTIFY):
            self._inject_error(CloseNotifyReceived())
        elif level == LEVEL_FATAL:
            self._inject_error(FatalDTLSError(code))
        else:
            self.log.warning("Unhandled alert level %d code %d", level, code)

    # transport protocol

    class SingleConnection:
        @classmethod
        def factory(cls, parent):
            return functools.partial(cls, weakref.ref(parent))

        def __init__(self, parent):
            self.parent = parent #: DTLSClientConnection

        def connection_made(self, transport):
            # only for for shutdown
            self.transport = transport

        def connection_lost(self, exc):
            pass

        def error_received(self, exc):
            parent = self.parent()
            if parent is None:
                self.transport.close()
                return
            parent._inject_error(exc)

        def datagram_received(self, data, addr):
            parent = self.parent()
            if parent is None:
                self.transport.close()
                return
            parent._dtls_socket.handleMessage(parent._connection, data)

class MessageInterfaceTinyDTLS(interfaces.MessageInterface):
    def __init__(self, ctx: interfaces.MessageManager, log, loop):
        self._pool = weakref.WeakValueDictionary({}) # see _connection_for_address

        self.ctx = ctx

        self.log = log
        self.loop = loop

    def _connection_for_address(self, host, port, pskId, psk):
        """Return a DTLSConnection to a given address. This will always give
        the same result for the same host/port combination, at least for as
        long as that result is kept alive (eg. by messages referring to it in
        their .remote) and while the connection has not failed."""

        try:
            return self._pool[(host, port, pskId)]
        except KeyError:
            self.log.info("No DTLS connection active to (%s, %s, %s), creating one", host, port, pskId)
            connection = DTLSClientConnection(host, port, pskId, psk, self)
            self._pool[(host, port, pskId)] = connection
            return connection

    @classmethod
    async def create_client_transport_endpoint(cls, ctx: interfaces.MessageManager, log, loop):
        return cls(ctx, log, loop)

    async def recognize_remote(self, remote):
        return isinstance(remote, DTLSClientConnection) and remote in self._pool.values()

    async def determine_remote(self, request):
        if request.requested_scheme != 'coaps':
            return None

        if request.unresolved_remote:
            host, port = hostportsplit(request.unresolved_remote)
            port = port or COAPS_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAPS_PORT
        else:
            raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

        dtlsparams = self.ctx.client_credentials.credentials_from_request(request)
        try:
            pskId, psk = dtlsparams.as_dtls_psk()
        except AttributeError:
            raise CredentialsMissingError("Credentials for requested URI are not compatible with DTLS-PSK")
        result = self._connection_for_address(host, port, pskId, psk)
        return result

    def send(self, message):
        message.remote.send(message.encode())

    async def shutdown(self):
        remaining_connections = list(self._pool.values())
        for c in remaining_connections:
            c.shutdown()
