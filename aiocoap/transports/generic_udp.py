# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import urllib

from aiocoap import interfaces, error
from aiocoap import COAP_PORT, Message

class GenericTransportEndpoint(interfaces.TransportEndpoint):
    """GenericTransportEndpoint is not a standalone implementation of a
    transport. It does implement everything between the TransportEndpoint
    interface and a not yet fully specified interface of "bound UDP
    sockets"."""

    def __init__(self, new_message_callback, new_error_callback, log, loop):
        self._new_message_callback = new_message_callback
        self._new_error_callback = new_error_callback
        self._log = log
        self._loop = loop

    @asyncio.coroutine
    def determine_remote(self, request):
        if request.requested_scheme not in ('coap', None):
            return None

        if request.unresolved_remote is not None:
            pseudoparsed = urllib.parse.SplitResult(None, request.unresolved_remote, None, None, None)
            host = pseudoparsed.hostname
            port = pseudoparsed.port or COAP_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAP_PORT
        else:
            raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

        return (yield from self._pool.connect((host, port)))

    def _received_datagram(self, address, datagram):
        try:
            message = Message.decode(datagram, remote=address)
        except error.UnparsableMessage:
            self._log.warning("Ignoring unparsable message from %s"%(address,))
            return

        self._new_message_callback(message)

    def _received_exception(self, address, exception):
        self._new_error_callback(exception.errno, address)

    def send(self, message):
        message.remote.send(message.encode())

    @asyncio.coroutine
    def shutdown(self):
        yield from self._pool.shutdown()
        self._new_message_callback = None
        self._new_error_callback = None
