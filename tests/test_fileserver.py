# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests for the file server.

This expects a file server at a CoAP server's root directory to be empty; files
are created, and different ways of triggering conflict responses are triggered
(eg. by overwriting a file, and then attempting to overwrite it with a
different one expecting the old state).
"""

import argparse
import asyncio
import os
import sys
import tempfile
import unittest

import aiocoap
from aiocoap import Message
from aiocoap.numbers.codes import *
from aiocoap.util import hostportjoin

from .common import PYTHON_PREFIX, CapturingSubprocess
from .test_server import WithClient

SERVER_NETLOC = hostportjoin("::1", None)
AIOCOAP_FILESERVER = PYTHON_PREFIX + [
    "./aiocoap-fileserver",
    "--write",
    "--bind",
    SERVER_NETLOC,
]


@unittest.skipIf(
    aiocoap.defaults.linkheader_missing_modules(),
    "Module missing for running fileserver tests: %s"
    % (aiocoap.defaults.linkheader_missing_modules(),),
)
class WithFileServer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        ready = asyncio.get_event_loop().create_future()
        self.__done = asyncio.get_event_loop().create_future()

        self.filedir = tempfile.mkdtemp(suffix="-fileserver")

        self.__task = asyncio.get_event_loop().create_task(
            self.run_server(ready, self.__done)
        )
        await ready

    # This might be overly complex; it was stripped down from the more intricate OSCORE plug tests
    async def run_server(self, readiness, done):
        self.process, process_outputs = await asyncio.get_event_loop().subprocess_exec(
            CapturingSubprocess,
            *(AIOCOAP_FILESERVER + ["-vvvvvvvv"]),
            self.filedir,
            stdin=None,
        )

        while True:
            if b"Server ready to receive requests" in process_outputs.stderr:
                break
            if self.process.get_returncode() is not None:
                readiness.set_exception(
                    RuntimeError(
                        "File server process terminated during startup:\n%s\n%s"
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

        done.set_result(
            (
                self.process.get_returncode(),
                process_outputs.stdout,
                process_outputs.stderr,
            )
        )

        self.process.close()

    async def asyncTearDown(self):
        # Don't leave this over, even if anything is raised during teardown
        self.process.terminate()

        # Checking whether it's empty
        os.rmdir(self.filedir)

        super().tearDown()

        code, out, err = await self.__done


class TestFileServer(WithFileServer, WithClient):
    async def test_fullcycle(self):
        await work_fileserver(
            self.client, "coap://%s/" % SERVER_NETLOC, self.assertTrue
        )


# Implemented as a single function to ease use from the command line
async def work_fileserver(ctx, base_uri, assert_):
    assert_(
        base_uri.endswith("/") and base_uri.count("/") == 3,
        "Base URI needs to be of shape coapsomething://hostname/ "
        "(with precisely these slashes)",
    )

    req = Message(code=GET, uri=base_uri)
    res = await ctx.request(req).response_raising
    assert_(res.code == CONTENT)
    assert_(res.opt.content_format == 40, "Directory listing is not in link-format")
    assert_(res.payload == b"", "Directory is initially not empty")

    file1_body = b"Hello World\n" * 200
    req = Message(code=PUT, uri=base_uri + "file", payload=file1_body)
    res = await ctx.request(req).response_raising
    assert_(res.code == CHANGED)
    early_etag = res.opt.etag
    assert_(early_etag is not None, "PUT did not already send an ETag")

    # TBD: Could persist a content format

    req = Message(code=GET, uri=base_uri + "file")
    res = await ctx.request(req).response_raising
    assert_(res.code == CONTENT)
    assert_(res.payload == file1_body)
    etag1 = res.opt.etag
    assert_(etag1 == early_etag, "PUT response ETag is not GET response ETag")
    assert_(etag1 is not None, "No ETag returned")

    # Revalidate
    req = Message(code=GET, uri=base_uri + "file", etags=[b"synthetic", etag1])
    res = await ctx.request(req).response_raising
    assert_(res.code == VALID)
    assert_(not res.payload)
    assert_(res.opt.etag == etag1)

    file2_body = b"It is different now."
    req = Message(
        code=PUT, uri=base_uri + "file", payload=file2_body, if_none_match=True
    )
    res = await ctx.request(req).response
    assert_(
        res.code == PRECONDITION_FAILED,
        "Overwrite succeeded even though expected empty",
    )

    req = Message(
        code=PUT, uri=base_uri + "file", payload=file2_body, if_match=[b"synthetic"]
    )
    res = await ctx.request(req).response
    assert_(
        res.code == PRECONDITION_FAILED,
        "Overwrite succeeded even though expected to conflict",
    )

    req = Message(code=PUT, uri=base_uri + "file", payload=file2_body, if_match=[etag1])
    res = await ctx.request(req).response_raising
    assert_(res.code == CHANGED)

    # Empty ETag is actually illegal, but the workaround to force the server to
    # send one is even cruder, see
    # https://github.com/core-wg/corrclar/issues/46
    #
    # This is not needed with the original body because that is blockwise'd.
    req = Message(code=GET, uri=base_uri + "file", etag=b"")
    res = await ctx.request(req).response_raising
    assert_(res.code == CONTENT)
    assert_(res.payload == file2_body)
    etag2 = res.opt.etag
    assert_(etag2 is not None, "No ETag returned")

    req = Message(code=DELETE, uri=base_uri + "file", if_match=[b"not the one"])
    res = await ctx.request(req).response
    assert_(
        res.code == PRECONDITION_FAILED,
        "Deletion should not pass with a non-matching ETag",
    )

    # Actual cleanup
    req = Message(code=DELETE, uri=base_uri + "file", if_match=[etag2])
    res = await ctx.request(req).response_raising
    assert_(res.code == DELETED)

    # Just to be sure
    req = Message(code=DELETE, uri=base_uri + "file")
    res = await ctx.request(req).response
    assert_(res.code == NOT_FOUND)  # DELETED might be OK too under idempotency rules?


async def run_standalone():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("base_uri")
    args = p.parse_args()

    ctx = await aiocoap.Context.create_client_context()

    def assert_(truth, error=""):
        if not truth:
            print("Assertion failed:", error)
            sys.exit(1)

    await work_fileserver(ctx, args.base_uri, assert_)


if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_fileserver`
    asyncio.run(run_standalone())
