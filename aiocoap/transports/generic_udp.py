# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from aiocoap import interfaces, error, util
from aiocoap import COAP_PORT, Message

class GenericMessageInterface(interfaces.MessageInterface):
    """GenericMessageInterface is not a standalone implementation of a
    message inteface. It does implement everything between the MessageInterface
    and a not yet fully specified interface of "bound UDP sockets"."""

    def __init__(self, ctx: interfaces.MessageManager, log, loop):
        self._ctx = ctx
        self._log = log
        self._loop = loop

    async def determine_remote(self, request):
        if request.requested_scheme not in ('coap', None):
            return None

        if request.unresolved_remote is not None:
            host, port = util.hostportsplit(request.unresolved_remote)
            port = port or COAP_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAP_PORT
        else:
            raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

        return await self._pool.connect((host, port))

    def _received_datagram(self, address, datagram):
        try:
            message = Message.decode(datagram, remote=address)
        except error.UnparsableMessage:
            self._log.warning("Ignoring unparsable message from %s", address)
            return

        self._ctx.dispatch_message(message)

    def _received_exception(self, address, exception):
        self._ctx.dispatch_error(exception.errno, address)

    def send(self, message):
        if self._ctx is None:
            self._log.info("Not sending message %r: transport is already shutting down.", message)
        else:
            message.remote.send(message.encode())

    async def shutdown(self):
        await self._pool.shutdown()
        self._ctx = None
