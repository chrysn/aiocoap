# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Confront an aiocoap server with a client that speaks so bad protocol it is
easier to mock with sending byte sequences than with aiocoap"""

import sys
import socket
import asyncio
import signal
import contextlib
import os
import unittest

import aiocoap

from .test_server import WithTestServer, precise_warnings, no_warnings, asynctest

# For some reasons site-local requests do not work on my test setup, resorting
# to link-local; that means a link needs to be given, and while we never need
# to find the default multicast interface to join MC groups, we need to know it
# to address them. This needs support from outside the test suite right now.
_skip_unless_defaultmcif = unittest.skipIf(
        "AIOCOAP_TEST_MCIF" not in os.environ,
        "Multicast tests require AIOCOAP_TEST_MCIF environment variable to tell"
        " the default multicast interface")

# Windows has no SIGALRM and thus can't do the timeouts. Only when the mocksock
# becomes async, those can be tested.
_skip_on_win32 = unittest.skipIf(
        sys.platform == 'win32',
        "Mock socket needs platform support for SIGALRM"
        )

class TimeoutError(RuntimeError):
    """Raised when a non-async operation times out"""

    @classmethod
    def _signalhandler(cls, *args):
        raise cls()

    @classmethod
    @contextlib.contextmanager
    def after(cls, time):
        old = signal.signal(signal.SIGALRM, cls._signalhandler)
        signal.alarm(time)
        yield
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

class WithMockSock(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.mocksock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    def tearDown(self):
        self.mocksock.close()

        super().tearDown()

class TestNoncoapClient(WithTestServer, WithMockSock):
    def setUp(self):
        super().setUp()

        self.mocksock.connect((self.serveraddress, aiocoap.COAP_PORT))

    @precise_warnings(["Ignoring unparsable message from ..."])
    @asynctest
    async def test_veryshort(self):
        self.mocksock.send(b'\x40')
        await asyncio.sleep(0.1)

    @precise_warnings(["Ignoring unparsable message from ..."])
    @asynctest
    async def test_short_mid(self):
        self.mocksock.send(b'\x40\x01\x97')
        await asyncio.sleep(0.1)

    @precise_warnings(["Ignoring unparsable message from ..."])
    @asynctest
    async def test_version2(self):
        self.mocksock.send(b'\x80\x01\x99\x98')
        await asyncio.sleep(0.1)

    @_skip_on_win32
    @no_warnings
    @asynctest
    async def test_duplicate(self):
        self.mocksock.send(b'\x40\x01\x99\x99') # that's a GET /
        await asyncio.sleep(0.1)
        self.mocksock.send(b'\x40\x01\x99\x99') # that's a GET /
        await asyncio.sleep(0.1)
        r1 = r2 = None
        try:
            with TimeoutError.after(1):
                r1 = self.mocksock.recv(1024)
                r2 = self.mocksock.recv(1024)
        except TimeoutError:
            pass
        self.assertEqual(r1, r2, "Duplicate GETs gave different responses")
        self.assertTrue(r1 is not None, "No responses received to duplicate GET")

    @_skip_on_win32
    @no_warnings
    @asynctest
    async def test_ping(self):
        self.mocksock.send(b'\x40\x00\x99\x9a') # CoAP ping -- should this test be doable in aiocoap?
        await asyncio.sleep(0.1)
        with TimeoutError.after(1):
            response = self.mocksock.recv(1024)
        assert response == b'\x70\x00\x99\x9a'

    @_skip_on_win32
    @no_warnings
    @asynctest
    async def test_noresponse(self):
        self.mocksock.send(b'\x50\x01\x99\x9b\xd1\xf5\x02') # CoAP NON GET / with no-response on 2.xx
        await asyncio.sleep(0.1)
        try:
            with TimeoutError.after(1):
                response = self.mocksock.recv(1024)
            self.assertTrue(False, "Response was sent when No-Response should have suppressed it")
        except TimeoutError:
            pass

    @_skip_on_win32
    @no_warnings
    @asynctest
    async def test_unknownresponse_reset(self):
        self.mocksock.send(bytes.fromhex("4040ffff"))
        await asyncio.sleep(0.1)
        with TimeoutError.after(1):
            response = self.mocksock.recv(1024)
        self.assertEqual(response, bytes.fromhex("7000ffff"), "Unknown CON Response did not trigger RST")

# Skipping the whole class when no multicast address was given (as otherwise
# it'd try binding :: which is bound to fail with a simplesocketserver setting)
@_skip_unless_defaultmcif
class TestNoncoapMulticastClient(WithTestServer, WithMockSock):
    # This exposes the test server to traffic from the environment system for
    # some time; it's only run if a default multicast inteface is given
    # explicitly, though.
    serveraddress = '::'

    @no_warnings
    @asynctest
    async def test_mutlicast_ping(self):
        # exactly like the unicast case -- just to verify we're actually reaching our server
        self.mocksock.sendto(b'\x40\x00\x99\x9a', (aiocoap.numbers.constants.MCAST_IPV6_LINKLOCAL_ALLCOAPNODES, aiocoap.COAP_PORT, 0, socket.if_nametoindex(os.environ['AIOCOAP_TEST_MCIF'])))
        await asyncio.sleep(0.1)
        with TimeoutError.after(1):
            response = self.mocksock.recv(1024)
        assert response == b'\x70\x00\x99\x9a'

    @no_warnings
    @asynctest
    async def test_multicast_unknownresponse_noreset(self):
        self.mocksock.sendto(bytes.fromhex("4040ffff"), (aiocoap.numbers.constants.MCAST_IPV6_LINKLOCAL_ALLCOAPNODES, aiocoap.COAP_PORT, 0, socket.if_nametoindex(os.environ['AIOCOAP_TEST_MCIF'])))
        await asyncio.sleep(0.1)
        try:
            with TimeoutError.after(1):
                response = self.mocksock.recv(1024)
        except TimeoutError:
            pass
        else:
            self.assertEqual(False, "Message was sent back responding to CON response to multicast address")
