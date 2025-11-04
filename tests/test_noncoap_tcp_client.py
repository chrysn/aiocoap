# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Confront a CoAP over TCP server with a client that speaks so bad protocol it
is easier to mock with sending byte sequences than with aiocoap"""

import asyncio
import unittest
import aiocoap

from .fixtures import precise_warnings, no_warnings
from .test_server import WithTestServer
from .common import tcp_disabled


@unittest.skipIf(tcp_disabled, "TCP disabled in environment")
class TestNoncoapTCPClient(WithTestServer):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.mock_r, self.mock_w = await asyncio.open_connection(
            self.serveraddress, aiocoap.COAP_PORT
        )

    async def asyncTearDown(self):
        self.mock_w.close()
        await super().asyncTearDown()

    @staticmethod
    def _read_as_messages(encoded: bytes):
        """Process the encoded data into CoAP-over-TCP messages, return them as
        a list and trailing (unrecognized / incomplete) data."""
        messages = []
        while True:
            size = aiocoap.transports.tcp._extract_message_size(encoded)
            if size is not None:
                size = sum(size)
            if size is None or size > len(encoded):
                return messages, encoded

            messages.append(aiocoap.transports.tcp._decode_message(encoded[:size]))
            encoded = encoded[size:]

    async def should_abort_early(self, request: bytes):
        """Send request bytes, expect that the server closes the connection
        after having sent possibly a CSM and an abort"""
        self.mock_w.write(request)
        r = (
            await self.mock_r.read()
        )  # timing out would be a typical failure case here too
        parsed, trail = self._read_as_messages(r)
        self.assertEqual(trail, b"", "Leftover data after closing message")
        if parsed[0].code == aiocoap.CSM:
            # don't discard the CSM unconditionallly: the server might have
            # read the request data before sending its own initial CSM.
            parsed.pop(0)
        self.assertEqual(
            len(parsed), 1, "Not exactly one (presumably abort) message received"
        )
        self.assertEqual(
            parsed[0].code, aiocoap.ABORT, "Received message is not an abort message"
        )

    async def should_idle(self, request: bytes, timeout=0.1):
        """Send request bytes, expect that the server sends CSM and does not
        close the connection, awaiting more from the client.

        Returns all messages received until the timeout."""
        self.mock_w.write(request)
        triggered_eof = False

        async def kill_read():
            """After a timeout, synthesize an end-of-file condition into the
            reader, hoping this doesn't beak too much."""
            nonlocal triggered_eof
            await asyncio.sleep(timeout)
            triggered_eof = True
            self.mock_r.feed_eof()

        asyncio.get_event_loop().create_task(kill_read())
        r = (
            await self.mock_r.read()
        )  # timing out would be a typical failure case here too
        self.assertEqual(triggered_eof, True, "Server closed connection prematurely")

        parsed, trail = self._read_as_messages(r)
        # if this happens, the server is either sending garbage (announcing
        # something long and not following up), or the timeout should be
        # increased
        self.assertEqual(trail, b"", "Leftover data after reading timeout")
        if parsed[0].code == aiocoap.CSM:
            # don't discard the CSM unconditionallly: the server might have
            # read the request data before sending its own initial CSM.
            parsed.pop(0)

        return parsed

    async def should_idle_quietly(self, request: bytes, timeout=0.1):
        """should_idle, but assert that no messages were returned"""

        messages = await self.should_idle(request, timeout)

        # it's not a per-spec wrong thing to do, but highly unusual
        self.assertEqual(messages, [], "Server sent messages on its own")

    @precise_warnings(["Aborting connection: Failed to parse message"])
    async def test_http_get(self):
        await self.should_abort_early(b"GET /.well-known/core HTTP/1.0")

    @precise_warnings(["Aborting connection: No CSM received"])
    async def test_early_get(self):
        await self.should_abort_early(b"\0\x01")

    @no_warnings
    async def test_incomplete_small(self):
        await self.should_idle_quietly(b"\0")

    @no_warnings
    async def test_incomplete_large1(self):
        # announcing but not sending 1 bytes extlen
        await self.should_idle_quietly(b"\xd0")

    @no_warnings
    async def test_incomplete_large2(self):
        # sending one out of four bytes extlen
        # a server could in theory reject this on grounds of "no matter what
        # you say next, my buffer ain't large enough"
        await self.should_idle_quietly(b"\xf0\0")

    @no_warnings
    async def test_incomplete_large3(self):
        # announcing a 269 byte long message, but not even sending the code
        await self.should_idle_quietly(b"\xe0\0\0")

    @precise_warnings(["Aborting connection: Overly large message announced"])
    async def test_incomplete_large4(self):
        # announcing the longest possible message, this should exceed
        # everyone's max-message-size.
        #
        # blocking to read more would be acceptable behavior as well.
        await self.should_abort_early(b"\xf0\xff\xff\xff\xff")

    @precise_warnings(["Aborting connection: Failed to parse message"])
    async def test_wrong_tkl(self):
        # send an unspecified token length of 15.
        # the rest of the message is an empty CSM, so if the server were to
        # extrapolate from the meaning of tkl 0..8, it'd read it as OK.
        await self.should_abort_early(b"\x0fxxxxxxxxxxxxxxx\xe1")

    # Fun inside the CSM

    @no_warnings
    async def test_exotic_elective_csm_option(self):
        # send option number something-even (something-odd plus 269) as an empty option
        await self.should_idle_quietly(b"\x30\xe1\xe0\xf1\xf1")

    @precise_warnings(["Aborting connection: Option not supported"])
    async def test_exotic_compulsory_csm_option(self):
        # send option number something-odd (something-even plus 269) as an empty option
        await self.should_abort_early(b"\x30\xe1\xe0\xf2\xf2")

    @precise_warnings(["Aborting connection: Option not supported"])
    async def test_exotic_compulsory_csm_option_late(self):
        # send an empty CSM, and after that the one from compulsory_csm_option
        await self.should_abort_early(b"\0\xe1\x30\xe1\xe0\xf2\xf2")
