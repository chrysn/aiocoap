# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module implements a TransportEndpoint that handles coaps:// using a
wrapped tinydtls library.

In order for this to run, the tinydtls cython wrapper from
https://git.fslab.de/jkonra2m/tinydtls must be available:

    $ git clone https://git.fslab.de/jkonra2m/tinydtls
    $ cd tinydtls
    $ autoreconf
    $ ./configure --with-ecc
    $ make
    $ cd cython
    $ python3 setup.py build_ext --inplace

That cython directory must be in PYTHONPATH / sys.path.
"""

import urllib.parse
import asyncio
import weakref
import socket

from ..message import Message
from .. import interfaces, error
from ..numbers import COAPS_PORT

import dtls

# tinyDTLS passes address information around in its session data, but the way
# it's used here that will be ignored; this is the data that is sent to / read
# from the tinyDTLS functions
_SENTINEL_ADDRESS = "::1"
_SENTINEL_PORT = 1234

DTLS_EVENT_CONNECT = 0x01DC
DTLS_EVENT_CONNECTED = 0x01DE
DTLS_EVENT_RENEGOTIATE = 0x01DF

class DTLSClientConnection:
    # for now i'd assyme the connection can double as an address. this means it
    # must be able to reconnect, and to manage itself as a member of a pool.

    # actually .remote probably needs to be split into different aspects, and
    # then this will fall apart; in particular:
    # * "Address where this must come from in order to match the request"
    # * "Address where to send a package that I want to send to where I
    #    previously sent something else" (and my own address might have changed)
    # * possibly something else too
    #
    # for now i'm ignoring that (FIXME this means that some MUST of the spec
    # are not met!)

    is_multicast = False

    def send(self, message):
        self._dtls_socket.write(self._connection, message)

    log = property(lambda self: self.main.log)

    @classmethod
    @asyncio.coroutine
    def start(cls, host, port, main):
        transport, self = yield from main.loop.create_datagram_endpoint(cls,
                remote_addr=(host, port),
                )

        self.main = main

        self._transport = transport

        self._dtls_socket = dtls.DTLS(
                read=self._read,
                write=self._write,
                event=self._event,
                pskId=b"Client_identity",
                pskStore={b"Client_identity": b"secretPSK"},
                )
        self._connection = self._dtls_socket.connect(_SENTINEL_ADDRESS, _SENTINEL_PORT)

        self._connecting = asyncio.Future()
        yield from self._connecting
        del self._connecting

        return self

    def shutdown(self):
        self._dtls_socket.close(self._connection)

    # dtls callbacks

    def _read(self, sender, data):
        # ignoring sender: it's only _SENTINEL_*

        try:
            message = Message.decode(data, self)
        except error.UnparsableMessage:
            self.log.warning("Ignoring unparsable message from %s"%(address,))
            return

        self.main.new_message_callback(message)

        return len(data)

    def _write(self, recipient, data):
        # ignoring recipient: it's only _SENTINEL_*
        self._transport.sendto(data)
        return len(data)

    def _event(self, level, code):
        if level == 0:
            # non-alert
            if code == DTLS_EVENT_CONNECT:
                return
            if code == DTLS_EVENT_CONNECTED:
                self._connecting.set_result(True)
                return
            self.log.warning("Unknown event received: code %d", code)
        else:
            self.log.warning("Unhandled alert level %d code %d", level, code)

    # transport protocol

    def connection_made(self, transport):
        pass # already handled in .start()

    def connection_lost(self, exc):
        print("Oups, the connection was lost:", exc)

    def error_received(self, exc):
        print("Error received", exc)

    def datagram_received(self, data, addr):
        self._dtls_socket.handleMessage(self._connection, data, False)

class TransportEndpointTinyDTLS(interfaces.TransportEndpoint):
    def __init__(self, new_message_callback, new_error_callback, log, loop):
        self._pool = weakref.WeakValueDictionary({}) # see _connection_for_address

        self.new_message_callback = new_message_callback
        self.new_error_callback = new_error_callback
        self.log = log
        self.loop = loop

    @asyncio.coroutine
    def _connection_for_address(self, host, port):
        """Return a DTLSConnection to a given address. This will always give
        the same result for the same host/port combination, at least for as
        long as that result is kept alive (eg. by messages referring to it in
        their .remote)."""

        try:
            return self._pool[(host, port)]
        except KeyError:
            # FIXME this would need locking so it's bad design
            connection = yield from DTLSClientConnection.start(host, port, self)
            self._pool[(host, port)] = connection
            return connection

    @classmethod
    @asyncio.coroutine
    def create_client_transport_endpoint(cls, new_message_callback, new_error_callback, log, loop, dump_to):
        if dump_to is not None:
            self.error("Ignoring dump_to in tinyDTLS transport endpoint")
        return cls(new_message_callback, new_error_callback, log, loop)

    @asyncio.coroutine
    def determine_remote(self, request):
        if request.requested_scheme != 'coaps':
            return None

        if request.unresolved_remote:
            pseudoparsed = urllib.parse.SplitResult(None, request.unresolved_remote, None, None, None)
            host = pseudoparsed.hostname
            port = pseudoparsed.port or COAPS_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAPS_PORT
        else:
            raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

        result = yield from self._connection_for_address(host, port)
        return result

    def send(self, message):
        message.remote.send(message.encode())

    @asyncio.coroutine
    def shutdown(self):
        remaining_connections = list(self._pool.values())
        for c in remaining_connections:
            c.shutdown()
