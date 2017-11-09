# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Run the OSCORE plug test"""

import sys
import asyncio
import unittest

import aiocoap
import aiocoap.defaults

from .test_server import WithAsyncLoop, WithClient
from . import common

from .common import PYTHON_PREFIX
SERVER_ADDRESS = '::1'
SERVER = PYTHON_PREFIX + ['./contrib/oscore-plugtest/plugtest-server', '--server-address', SERVER_ADDRESS]
CLIENT = PYTHON_PREFIX + ['./contrib/oscore-plugtest/plugtest-client']

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

@unittest.skipIf(sys.version_info < (3, 5), "OSCORE plug test server uses Python 3.5 'async def' idioms")
@unittest.skipIf(aiocoap.defaults.oscore_missing_modules(), "Mdules missing for running OSCORE tests: %s"%(aiocoap.defaults.oscore_missing_modules(),))
class WithPlugtestServer(WithAsyncLoop, WithAssertNofaillines):
    def setUp(self):
        super(WithPlugtestServer, self).setUp()
        ready = asyncio.Future()
        self.__done = asyncio.Future()
        self.__task = asyncio.Task(self.run_server(ready, self.__done))
        self.loop.run_until_complete(ready)

    @asyncio.coroutine
    def run_server(self, readiness, done):
        self.process = yield from asyncio.create_subprocess_exec(
                *SERVER,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
                )
        while True:
            l = yield from self.process.stdout.readline()
            if l == b"":
                try:
                    _, err = yield from self.process.communicate()
                    message = err.decode('utf8')
                except BaseException as e:
                    message = str(e)
                finally:
                    readiness.set_exception(RuntimeError("OSCORE server process terminated during startup: %s."%message))
                return
            if l == b'Plugtest server ready.\n':
                break
        readiness.set_result(True)

        out, err = yield from self.process.communicate()

        done.set_result((out, err))

    def tearDown(self):
        self.process.terminate()

        out, err = self.loop.run_until_complete(self.__done)

        self.assertNoFaillines(out, '"failed" showed up in plugtest server stdout')
        self.assertNoFaillines(err, '"failed" showed up in plugtest server stderr')

class TestOSCOREPlugtest(WithPlugtestServer, WithClient, WithAssertNofaillines):

    @asyncio.coroutine
    def _test_plugtestclient(self, x):
        set_seqno = aiocoap.Message(code=aiocoap.PUT, uri='coap://%s/sequence-numbers'%(common.loopbackname_v6 or common.loopbackname_v46), payload=str(x).encode('ascii'))
        yield from self.client.request(set_seqno).response_raising

        proc = yield from asyncio.create_subprocess_exec(*(CLIENT + ['[' + SERVER_ADDRESS + ']', str(x)]), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = yield from proc.communicate()

        self.assertNoFaillines(out, '"failed" showed up in plugtest client stdout')
        self.assertNoFaillines(err, '"failed" showed up in plugtest client stderr')
        self.assertEqual(proc.returncode, 0, 'Plugtest client return non-zero exit state\nOutput was:\n' + out.decode('utf8') + '\nErrorr output was:\n' + err.decode('utf8'))

for x in range(0, 13):
    test = lambda self, x=x: self.loop.run_until_complete(self._test_plugtestclient(x))
    setattr(TestOSCOREPlugtest, 'test_%d'%x, test)
