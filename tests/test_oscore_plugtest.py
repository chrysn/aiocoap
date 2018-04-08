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
from aiocoap.util import hostportjoin

from .test_server import WithAsyncLoop, WithClient, asynctest
from . import common
from .fixtures import test_is_successful

from .common import PYTHON_PREFIX
SERVER_ADDRESS = '::1'
SERVER = PYTHON_PREFIX + ['./contrib/oscore-plugtest/plugtest-server', '--verbose', '--bind', hostportjoin(SERVER_ADDRESS, None)]
CLIENT = PYTHON_PREFIX + ['./contrib/oscore-plugtest/plugtest-client', '--verbose']

class WithAssertNofaillines(unittest.TestCase):
    def assertNoFaillines(self, text_to_check, message):
        """Assert that there are no lines that contain the phrase 'fail' or
        'WARNING'/'ERROR' in the output, unless they are a 'Check passed' line.

        This is to check the output of the plugtest client, which may
        successfully report: 'Check passed: The validation failed. (Tag
        invalid)'"""

        lines = text_to_check.decode('utf8').split('\n')
        lines = (l for l in lines if not l.startswith('Check passed:'))
        # explicitly whitelisted for when the server is run with increased verbosity
        lines = (l for l in lines if 'INFO:coap-server:Render request raised a renderable error' not in l)
        errorlines = (l for l in lines if 'fail'in l or 'WARNING' in l or 'ERROR' in l)
        self.assertEqual([], list(errorlines), message)

@unittest.skipIf(aiocoap.defaults.oscore_missing_modules(), "Mdules missing for running OSCORE tests: %s"%(aiocoap.defaults.oscore_missing_modules(),))
class WithPlugtestServer(WithAsyncLoop, WithAssertNofaillines):
    def setUp(self):
        super(WithPlugtestServer, self).setUp()
        ready = asyncio.Future()
        self.__done = asyncio.Future()
        self.__task = asyncio.Task(self.run_server(ready, self.__done))
        self.loop.run_until_complete(ready)

    async def run_server(self, readiness, done):
        self.process = await asyncio.create_subprocess_exec(
                *SERVER,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
                )
        while True:
            l = await self.process.stdout.readline()
            if l == b"":
                try:
                    _, err = await self.process.communicate()
                    message = err.decode('utf8')
                except BaseException as e:
                    message = str(e)
                finally:
                    readiness.set_exception(RuntimeError("OSCORE server process terminated during startup: %s."%message))
                return
            if l == b'Plugtest server ready.\n':
                break
        readiness.set_result(True)

        out, err = await self.process.communicate()

        done.set_result((out, err))

    def tearDown(self):
        self.process.terminate()

        out, err = self.loop.run_until_complete(self.__done)

        if not test_is_successful(self):
            if not out and not err:
                return
            self.fail("Previous errors occurred." +
                    ("\nServer stdout was:\n    " +
                        out.decode('utf8').replace("\n", "\n    ")
                    if out else "") +
                    ("\nServer stderr was:\n    " +
                            err.decode('utf8').replace("\n", "\n    ")
                    if err else ""))
        else:
            self.assertNoFaillines(out, '"failed" showed up in plugtest server stdout')
            self.assertNoFaillines(err, '"failed" showed up in plugtest server stderr')

class TestOSCOREPlugtest(WithPlugtestServer, WithClient, WithAssertNofaillines):

    @asynctest
    async def _test_plugtestclient(self, x):
        set_seqno = aiocoap.Message(code=aiocoap.PUT, uri='coap://%s/sequence-numbers'%(common.loopbackname_v6 or common.loopbackname_v46), payload=b'0')
        await self.client.request(set_seqno).response_raising

        proc = await asyncio.create_subprocess_exec(*(CLIENT + ['[' + SERVER_ADDRESS + ']', str(x)]), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        # this is a big workaround for (out, err) = proc.communicate() not
        # filling data into its output variables when raising a
        # CancellationError (admittedly, how should it; maybe have
        # `communicate(stdin, *, out_callback, err_callback)`?
        out = err = b""
        async def out_read():
            nonlocal out
            while True:
                data = await proc.stdout.readline()
                if not data:
                    return
                out += data
        async def err_read():
            nonlocal err
            while True:
                data = await proc.stderr.readline()
                if not data:
                    return
                err += data
        self.loop.create_task(out_read())
        self.loop.create_task(err_read())

        try:
            await proc.wait()
        except asyncio.CancelledError:
            proc.terminate()

        self.assertEqual(proc.returncode, 0, 'Plugtest client return non-zero exit state\nOutput was:\n' + out.decode('utf8') + '\nErrorr output was:\n' + err.decode('utf8'))
        self.assertNoFaillines(out, '"failed" showed up in plugtest client stdout')
        self.assertNoFaillines(err, '"failed" showed up in plugtest client stderr')

for x in range(0, 13):
    test = lambda self, x=x: self._test_plugtestclient(x)
    # enforcing them to sort properly is purely a readability thing, they
    # execute correctly out-of-order too.
    setattr(TestOSCOREPlugtest, 'test_%03d'%x, test)
