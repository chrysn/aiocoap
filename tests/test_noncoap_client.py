# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Confront an aiocoap server with a client that speaks so bad protocol it is
easier to mock with sending byte sequences than with aiocoap"""

import socket
import asyncio
from asyncio import wait_for, TimeoutError
import os
import unittest

import aiocoap

from .fixtures import precise_warnings, no_warnings
from .test_server import WithTestServer

# For some reasons site-local requests do not work on my test setup, resorting
# to link-local; that means a link needs to be given, and while we never need
# to find the default multicast interface to join MC groups, we need to know it
# to address them. This needs support from outside the test suite right now.
_skip_unless_defaultmcif = unittest.skipIf(
    "AIOCOAP_TEST_MCIF" not in os.environ,
    "Multicast tests require AIOCOAP_TEST_MCIF environment variable to tell"
    " the default multicast interface",
)


class MockSockProtocol:
    def __init__(self, remote_addr):
        # It should be pointed out here that this whole mocksock thing is not
        # terribly well thought out, and just hacked together to replace the
        # blocking sockets that used to be there (which were equally hacked
        # together)

        self.incoming_queue = asyncio.Queue()
        self.remote_addr = remote_addr

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.incoming_queue.put_nowait((data, addr))

    async def close(self):
        self.transport.close()

    def connection_lost(self, exc):
        # This is a datagram transport, it's only closed because we closed it
        pass

    # emulating the possibly connected socket.socket this once was

    def send(self, data):
        self.transport.sendto(data, self.remote_addr)

    def sendto(self, data, addr):
        self.transport.sendto(data, addr)

    async def recv(self):
        return (await self.incoming_queue.get())[0]


class WithMockSock(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        _, self.mocksock = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: MockSockProtocol(self.mocksock_remote_addr),
            family=socket.AF_INET6,
        )

    async def asyncTearDown(self):
        await self.mocksock.close()

        await super().asyncTearDown()


class TestNoncoapClient(WithTestServer, WithMockSock):
    async def asyncSetUp(self):
        self.mocksock_remote_addr = (self.serveraddress, aiocoap.COAP_PORT)

        await super().asyncSetUp()

    @precise_warnings(["Ignoring unparsable message from ..."])
    async def test_veryshort(self):
        self.mocksock.send(b"\x40")
        await asyncio.sleep(0.1)

    @precise_warnings(["Ignoring unparsable message from ..."])
    async def test_short_mid(self):
        self.mocksock.send(b"\x40\x01\x97")
        await asyncio.sleep(0.1)

    @precise_warnings(["Ignoring unparsable message from ..."])
    async def test_version2(self):
        self.mocksock.send(b"\x80\x01\x99\x98")
        await asyncio.sleep(0.1)

    @no_warnings
    async def test_duplicate(self):
        self.mocksock.send(b"\x40\x01\x99\x99")  # that's a GET /
        await asyncio.sleep(0.1)
        self.mocksock.send(b"\x40\x01\x99\x99")  # that's a GET /
        await asyncio.sleep(0.1)
        r1 = r2 = None
        try:
            r1 = await wait_for(self.mocksock.recv(), timeout=1)
            r2 = await wait_for(self.mocksock.recv(), timeout=1)
        except TimeoutError:
            pass
        self.assertEqual(r1, r2, "Duplicate GETs gave different responses")
        self.assertTrue(r1 is not None, "No responses received to duplicate GET")

    @no_warnings
    async def test_ping(self):
        self.mocksock.send(
            b"\x40\x00\x99\x9a"
        )  # CoAP ping -- should this test be doable in aiocoap?
        response = await asyncio.wait_for(self.mocksock.recv(), timeout=1)
        assert response == b"\x70\x00\x99\x9a"

    @no_warnings
    async def test_noresponse(self):
        self.mocksock.send(
            b"\x50\x01\x99\x9b\xd1\xf5\x02"
        )  # CoAP NON GET / with no-response on 2.xx
        try:
            response = await wait_for(self.mocksock.recv(), timeout=1)
            self.assertTrue(
                False, "Response was sent when No-Response should have suppressed it"
            )
        except TimeoutError:
            pass

    @no_warnings
    async def test_unknownresponse_reset(self):
        self.mocksock.send(
            bytes.fromhex("4040ffff")
        )  # CoAP CON 2.00 that the server has not sent a request for
        response = await wait_for(self.mocksock.recv(), timeout=1)
        self.assertEqual(
            response,
            bytes.fromhex("7000ffff"),
            "Unknown CON Response did not trigger RST",
        )

    @no_warnings
    async def test_unknownresponse_noreset(self):
        self.mocksock.send(
            bytes.fromhex("6040ffff")
        )  # CoAP ACK 2.00 that the server has not sent a request for
        try:
            response = await wait_for(self.mocksock.recv(), timeout=1)
            self.assertTrue(False, "Unknown ACK Response triggered something")
        except TimeoutError:
            pass


# Skipping the whole class when no multicast address was given (as otherwise
# it'd try binding :: which is bound to fail with a simplesocketserver setting)
@_skip_unless_defaultmcif
class TestNoncoapMulticastClient(WithTestServer, WithMockSock):
    # This exposes the test server to traffic from the environment system for
    # some time; it's only run if a default multicast inteface is given
    # explicitly, though.
    serveraddress = "::"

    async def asyncSetUp(self):
        # always used with sendto
        self.mocksock_remote_addr = None

        await super().asyncSetUp()

    @no_warnings
    async def test_mutlicast_ping(self):
        # exactly like the unicast case -- just to verify we're actually reaching our server
        self.mocksock.sendto(
            b"\x40\x00\x99\x9a",
            (
                aiocoap.numbers.constants.MCAST_IPV6_LINKLOCAL_ALLCOAPNODES,
                aiocoap.COAP_PORT,
                0,
                socket.if_nametoindex(os.environ["AIOCOAP_TEST_MCIF"]),
            ),
        )
        response = await wait_for(self.mocksock.recv(), timeout=1)
        assert response == b"\x70\x00\x99\x9a"

    @no_warnings
    async def test_multicast_unknownresponse_noreset(self):
        self.mocksock.sendto(
            bytes.fromhex("4040ffff"),
            (
                aiocoap.numbers.constants.MCAST_IPV6_LINKLOCAL_ALLCOAPNODES,
                aiocoap.COAP_PORT,
                0,
                socket.if_nametoindex(os.environ["AIOCOAP_TEST_MCIF"]),
            ),
        )
        try:
            response = await wait_for(self.mocksock.recv(), timeout=1)
        except TimeoutError:
            pass
        else:
            self.assertEqual(
                False,
                "Message was sent back responding to CON response to multicast address",
            )
