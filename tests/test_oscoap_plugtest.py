# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Run the OSCOAP plug test"""

import asyncio
import subprocess
import unittest

import aiocoap

from .test_server import WithAsyncLoop, WithClient

from .common import PYTHON_PREFIX
SERVER = PYTHON_PREFIX + ['./contrib/oscoap-plugtest/plugtest-server']
CLIENT = PYTHON_PREFIX + ['./contrib/oscoap-plugtest/plugtest-client']

class WithAssertNofaillines(unittest.TestCase):
    def assertNoFaillines(self, text_to_check, message):
        """Assert that there are no lines that contain the phrase 'fail' in the
        output, unless they are a 'Check passed' line.

        This is to check the output of the plugtest client, which may
        successfully report: 'Check passed: The validation failed. (Tag
        invalid)'"""

        lines = text_to_check.decode('utf8').split('\n')
        lines = (l for l in lines if not l.startswith('Check passed:'))
        errorlines = (l for l in lines if 'fail'in l)
        self.assertEqual([], list(errorlines), message)

class WithPlugtestServer(WithAsyncLoop, WithAssertNofaillines):
    def setUp(self):
        super(WithPlugtestServer, self).setUp()
        ready = asyncio.Future()
        self.__done = asyncio.Future()
        self.__task = asyncio.Task(self.run_server(ready, self.__done))
        self.loop.run_until_complete(ready)

    @asyncio.coroutine
    def run_server(self, readiness, done):
        self.process = yield from asyncio.create_subprocess_exec(*SERVER, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        yield from asyncio.sleep(0.2) # FIXME: wait for the server to display its "loop ready" message
        readiness.set_result(True)

        out, err = yield from self.process.communicate()

        done.set_result((out, err))

    def tearDown(self):
        self.process.terminate()

        out, err = self.loop.run_until_complete(self.__done)

        self.assertNoFaillines(out, '"failed" showed up in plugtest server stdout')
        self.assertNoFaillines(err, '"failed" showed up in plugtest server stderr')

class TestOSCOAPPlugtest(WithPlugtestServer, WithClient, WithAssertNofaillines):

    @asyncio.coroutine
    def _test_plugtestclient(self, x):
        set_seqno = aiocoap.Message(code=aiocoap.PUT, uri='coap://localhost/sequence-numbers', payload=str(x).encode('ascii'))
        yield from self.client.request(set_seqno).response_raising

        proc = yield from asyncio.create_subprocess_exec(*(CLIENT + ['localhost', str(x)]), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = yield from proc.communicate()

        self.assertNoFaillines(out, '"failed" showed up in plugtest client stdout')
        self.assertNoFaillines(err, '"failed" showed up in plugtest client stderr')

for x in range(1, 17):
    test = lambda self, x=x: self.loop.run_until_complete(self._test_plugtestclient(x))
    if 8 <= x <= 15:
        test = unittest.skip("Test requires operator to judge timeout")(test)
    setattr(TestOSCOAPPlugtest, 'test_%d'%x, test)
