# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from aiocoap import interfaces, error, util
from aiocoap import COAP_PORT, Message


class GenericMessageInterface(interfaces.MessageInterface):
    """GenericMessageInterface is not a standalone implementation of a
    message inteface. It does implement everything between the MessageInterface
    and a not yet fully specified interface of "bound UDP sockets".

    It delegates sending through the address objects (which persist through
    some time, given this is some kind of bound-socket scenario).

    The user must:
    * set up a ._pool after construction with a shutdown and a connect method
    * provide their addresses with a send(bytes) method
    * pass incoming data to the _received_datagram and _received_exception methods
    """

    def __init__(self, mman: interfaces.MessageManager, log, loop):
        self._mman = mman
        self._log = log
        self._loop = loop

    # Callbacks to be hooked up by the user of the class; feed data on to the
    # message manager

    def _received_datagram(self, address, datagram):
        try:
            message = Message.decode(datagram, remote=address)
        except error.UnparsableMessage:
            self._log.warning("Ignoring unparsable message from %s", address)
            return

        self._mman.dispatch_message(message)

    def _received_exception(self, address, exception):
        self._mman.dispatch_error(exception, address)

    # Implementations of MessageInterface

    def send(self, message):
        if self._mman is None:
            self._log.info(
                "Not sending message %r: transport is already shutting down.", message
            )
        else:
            message.remote.send(message.encode())

    async def shutdown(self):
        self._mman = None
        await self._pool.shutdown()

    async def determine_remote(self, request):
        if request.requested_scheme not in ("coap", None):
            return None

        if request.unresolved_remote is not None:
            host, port = util.hostportsplit(request.unresolved_remote)
            port = port or COAP_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAP_PORT
        else:
            raise ValueError(
                "No location found to send message to (neither in .opt.uri_host nor in .remote)"
            )

        if self._mman is None:
            raise error.LibraryShutdown

        result = await self._pool.connect((host, port))
        if request.remote.maximum_block_size_exp < result.maximum_block_size_exp:
            result.maximum_block_size_exp = request.remote.maximum_block_size_exp
        return result
