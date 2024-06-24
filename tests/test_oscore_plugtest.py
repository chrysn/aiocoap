# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Run the OSCORE plug test"""

import asyncio
import unittest
import tempfile
import shutil

import aiocoap
import aiocoap.defaults
from aiocoap.util import hostportjoin

from .test_server import WithAsyncLoop, WithClient, asynctest
from .fixtures import is_test_successful

from .common import PYTHON_PREFIX, CapturingSubprocess

SERVER_ADDRESS = "::1"
SERVER = PYTHON_PREFIX + [
    "./contrib/oscore-plugtest/plugtest-server",
    "--verbose",
    "--bind",
    hostportjoin(SERVER_ADDRESS, None),
]
CLIENT = PYTHON_PREFIX + ["./contrib/oscore-plugtest/plugtest-client", "--verbose"]

# those are to be expected to contain bad words -- 'Check passed: X failed' is legitimate
output_whitelist = ["Check passed: "]
# explicitly whitelisted for when the server is run with increased verbosity
debug_whitelist = [
    "INFO:coap-server:Render request raised a renderable error",
    "DEBUG:oscore-site:Will encrypt message as response: ",
]


class WithAssertNofaillines(unittest.TestCase):
    def assertNoFaillines(self, text_to_check, message):
        """Assert that there are no lines that contain the phrase 'fail' or
        'WARNING'/'ERROR' in the output, unless they are a 'Check passed' line
        or other whitelisted ones.

        This is to check the output of the plugtest client, which may
        successfully report: 'Check passed: The validation failed. (Tag
        invalid)'"""

        lines = text_to_check.decode("utf8").split("\n")
        lines = (
            l
            # "failed" and "error" are always legitimate in this position
            # as they happen by design; whereever they are unexpected,
            # they're caught by the regular plug test operation
            .replace("Precondition Failed", "Precondition @@@led").replace(
                "Internal Server Error", "Internal Server @@@or"
            )
            for l in lines
        )
        lines = (
            l
            for l in lines
            if not any(l.startswith(white) for white in output_whitelist)
        )
        lines = (l for l in lines if not any(white in l for white in debug_whitelist))
        errorlines = (
            l
            for l in lines
            if "fail" in l.lower() or "warning" in l.lower() or "error" in l.lower()
        )
        self.assertEqual([], list(errorlines), message)


@unittest.skipIf(
    aiocoap.defaults.oscore_missing_modules(),
    "Module missing for running OSCORE tests: %s"
    % (aiocoap.defaults.oscore_missing_modules(),),
)
class WithPlugtestServer(WithAsyncLoop, WithAssertNofaillines):
    def setUp(self):
        super(WithPlugtestServer, self).setUp()
        ready = self.loop.create_future()
        self.__done = self.loop.create_future()

        self.contextdir = tempfile.mkdtemp(suffix="-contexts")

        self.__task = self.loop.create_task(self.run_server(ready, self.__done))
        self.__task.add_done_callback(
            lambda _: None
            if ready.done()
            else ready.set_exception(self.__task.exception())
        )
        self.loop.run_until_complete(ready)

    async def run_server(self, readiness, done):
        self.process, process_outputs = await self.loop.subprocess_exec(
            CapturingSubprocess, *self.SERVER, self.contextdir + "/server", stdin=None
        )
        try:
            while True:
                if b"Plugtest server ready.\n" in process_outputs.stdout:
                    break
                if self.process.get_returncode() is not None:
                    readiness.set_exception(
                        RuntimeError(
                            "OSCORE server process terminated during startup:\n%s\n%s"
                            % (
                                process_outputs.stdout.decode("utf8"),
                                process_outputs.stderr.decode("utf8"),
                            )
                        )
                    )
                    return
                await process_outputs.read_more
            readiness.set_result(True)

            while True:
                if self.process.get_returncode() is not None:
                    break
                await process_outputs.read_more

            done.set_result((process_outputs.stdout, process_outputs.stderr))

        finally:
            self.process.close()

    def tearDown(self):
        # Don't leave this over, even if anything is raised during teardown
        self.process.terminate()

        super().tearDown()

        out, err = self.loop.run_until_complete(self.__done)

        if not is_test_successful(self):
            if not out and not err:
                return
            self.fail(
                "Previous errors occurred."
                + (
                    "\nServer stdout was:\n    "
                    + out.decode("utf8").replace("\n", "\n    ")
                    if out
                    else ""
                )
                + (
                    "\nServer stderr was:\n    "
                    + err.decode("utf8").replace("\n", "\n    ")
                    if err
                    else ""
                )
            )
        else:
            self.assertNoFaillines(out, '"failed" showed up in plugtest server stdout')
            self.assertNoFaillines(err, '"failed" showed up in plugtest server stderr')

        # Unlike the server process termination, leaving those around can be
        # helpful and barely does any harm.
        shutil.rmtree(self.contextdir)


class TestOSCOREPlugtestBase(WithPlugtestServer, WithClient, WithAssertNofaillines):
    @asynctest
    async def _test_plugtestclient(self, x):
        proc, transport = await self.loop.subprocess_exec(
            CapturingSubprocess,
            *(
                CLIENT
                + ["[" + SERVER_ADDRESS + "]", self.contextdir + "/client", str(x)]
            ),
            stdin=None,
        )

        try:
            while True:
                if proc.get_returncode() is not None:
                    break
                await transport.read_more
        except asyncio.CancelledError:
            proc.terminate()
        else:
            proc.close()

        self.assertEqual(
            proc.get_returncode(),
            0,
            "Plugtest client return non-zero exit state\nOutput was:\n"
            + transport.stdout.decode("utf8")
            + "\nErrorr output was:\n"
            + transport.stderr.decode("utf8"),
        )
        self.assertNoFaillines(
            transport.stdout, '"failed" showed up in plugtest client stdout'
        )
        self.assertNoFaillines(
            transport.stderr, '"failed" showed up in plugtest client stderr'
        )


class TestOSCOREPlugtestWithoutRecovery(TestOSCOREPlugtestBase):
    SERVER = SERVER


class TestOSCOREPlugtestWithRecovery(TestOSCOREPlugtestBase):
    SERVER = SERVER + ["--state-was-lost"]


for x in range(0, 17):
    for cls in (TestOSCOREPlugtestWithRecovery, TestOSCOREPlugtestWithoutRecovery):
        t = lambda self, x=x: self._test_plugtestclient(x)
        if x == 16:
            # That test can not succeed against a regular plugtest server
            t = unittest.expectedFailure(t)
        if x == 7:
            # That test fails because there is no proper observation cancellation
            # aroun yet, see https://github.com/chrysn/aiocoap/issues/104
            #
            # Not making a statement on whether this is ecpected to work or
            # not, because it is highly irregular (it works with setup.py test
            # and fails with tox?)
            continue

        # enforcing them to sort properly is purely a readability thing, they
        # execute correctly out-of-order too.
        setattr(cls, "test_%03d" % x, t)
    # Let's not leak a global that'd be picked up for testing, given these are
    # already being tested
    del cls
