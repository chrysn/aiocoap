# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Confront an aiocoap server with a client that speaks so bad protocol it is
easier to mock with sending byte sequences than with aiocoap"""

import socket
import asyncio
import signal
import contextlib

import aiocoap

from .test_server import WithTestServer, precise_warnings, no_warnings

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

class TestNoncoapClient(WithTestServer):
    def setUp(self):
        super(TestNoncoapClient, self).setUp()

        self.mocksock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.mocksock.connect((self.serveraddress, aiocoap.COAP_PORT))

    def tearDown(self):
        self.mocksock.close()

        super(TestNoncoapClient, self).tearDown()

    @precise_warnings(["Ignoring unparsable message from ..."])
    def test_veryshort(self):
        self.mocksock.send(b'\x40')
        self.loop.run_until_complete(asyncio.sleep(0.1))

    @precise_warnings(["Ignoring unparsable message from ..."])
    def test_short_mid(self):
        self.mocksock.send(b'\x40\x01\x97')
        self.loop.run_until_complete(asyncio.sleep(0.1))

    @precise_warnings(["Ignoring unparsable message from ..."])
    def test_version2(self):
        self.mocksock.send(b'\x80\x01\x99\x98')
        self.loop.run_until_complete(asyncio.sleep(0.1))

    @no_warnings
    def test_duplicate(self):
        self.mocksock.send(b'\x40\x01\x99\x99') # that's a GET /
        self.loop.run_until_complete(asyncio.sleep(0.1))
        self.mocksock.send(b'\x40\x01\x99\x99') # that's a GET /
        self.loop.run_until_complete(asyncio.sleep(0.1))
        with TimeoutError.after(1):
            r1 = self.mocksock.recv(1024)
            r2 = self.mocksock.recv(1024)
        self.assertEqual(r1, r2, "Duplicate GETs gave different responses")

    @no_warnings
    def test_ping(self):
        self.mocksock.send(b'\x40\x00\x99\x9a') # CoAP ping -- should this test be doable in aiocoap?
        self.loop.run_until_complete(asyncio.sleep(0.1))
        with TimeoutError.after(1):
            response = self.mocksock.recv(1024)
        assert response == b'\x70\x00\x99\x9a'
