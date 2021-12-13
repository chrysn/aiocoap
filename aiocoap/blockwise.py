# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Helpers for the implementation of RFC7959 blockwise transfers"""

import types

from . import numbers
from .numbers.optionnumbers import OptionNumber
from .error import ConstructionRenderableError
from .message import Message
from .optiontypes import BlockOption
from .util.asyncio.timeoutdict import TimeoutDict

def _extract_block_key(message):
    """Extract a key that hashes equally for all blocks of a blockwise
    operation from a request message.

    See discussion at <https://mailarchive.ietf.org/arch/msg/core/I-6LzAL6lIUVDA6_g9YM3Zjhg8E>.
    """

    return (message.remote.blockwise_key, message.code, message.get_cache_key([
        OptionNumber.BLOCK1,
        OptionNumber.BLOCK2,
        OptionNumber.OBSERVE,
        ]))

class ContinueException(ConstructionRenderableError):
    """Not an error in the CoAP sense, but an error in the processing sense,
    indicating that no complete request message is available for processing.

    It reflects back the request's block1 option when rendered.
    """
    def __init__(self, block1):
        self.block1 = block1

    def to_message(self):
        m = super().to_message()
        m.opt.block1 = self.block1
        return m

    code = numbers.CONTINUE

class IncompleteException(ConstructionRenderableError):
    code = numbers.REQUEST_ENTITY_INCOMPLETE

class Block1Spool:
    def __init__(self):
        # FIXME: introduce an actual parameter here
        self._assemblies = TimeoutDict(numbers.MAX_TRANSMIT_WAIT)

    def feed_and_take(self, req: Message) -> Message:
        """Assemble the request into the spool. This either produces a
        reassembled request message, or raises either a Continue or a Request
        Entity Incomplete exception.

        Requests without block1 are simply passed through."""

        if req.opt.block1 is None:
            return req

        block_key = _extract_block_key(req)

        if req.opt.block1.block_number == 0:
            # silently discarding any old incomplete operation
            self._assemblies[block_key] = req
        else:
            try:
                self._assemblies[block_key]._append_request_block(req)
            except KeyError:
                # KeyError: Received unmatched blockwise response
                # ValueError: Failed to assemble -- gaps or overlaps in data
                raise IncompleteException from None

        if req.opt.block1.more:
            raise ContinueException(req.opt.block1)
        else:
            return self._assemblies[block_key]
            # which happens to carry the last block's block1 option

class Block2Cache:
    """A cache of responses to a give block key.

    Use this when result rendering is expensive, not idempotent or has varying
    output -- otherwise it's often better to calculate the full response again
    and serve chunks.
    """
    def __init__(self):
        # FIXME: introduce an actual parameter here
        self._completes = TimeoutDict(numbers.MAX_TRANSMIT_WAIT)

    async def extract_or_insert(self, req: Message, response_builder: types.CoroutineType):
        """Given a request message,

        * if it is querying a particular block, look it up in the cache or
          raise Request Entity Incomplete.
        * otherwise,
          * await the response builder
          * return the response if it doesn't need chunking, or
          * return the first chunk and store it for later use

        """
        block_key = _extract_block_key(req)

        if req.opt.block2 is None or req.opt.block2.block_number == 0:
            assembled = await response_builder()
        else:
            try:
                assembled = self._completes[block_key]
            except KeyError:
                raise IncompleteException from None

        if len(assembled.payload) > req.remote.maximum_payload_size or \
                req.opt.block2 is not None and len(assembled.payload) > req.opt.block2.size:
            self._completes[block_key] = assembled

            block2 = req.opt.block2 or \
                    BlockOption.BlockwiseTuple(0, 0, req.remote.maximum_block_size_exp)
            return assembled._extract_block(
                    block2.block_number,
                    block2.size_exponent,
                    req.remote.maximum_payload_size
                    )
        else:
            return assembled
