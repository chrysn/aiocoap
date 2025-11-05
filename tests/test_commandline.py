# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This tests launch the command line utility aiocoap-client in a sub-process.

The aiocoap-proxy utility is tested in test_proxy inside this process as
orchestration of success reporting is not that easy with a daemon process;
aiocoap-rd might need to get tested in a similar way to -proxy."""

import asyncio
import subprocess
import unittest
import os

import aiocoap.defaults

from .test_server import WithTestServer, no_warnings
from .common import PYTHON_PREFIX, using_simple6, in_woodpecker

linkheader_modules = aiocoap.defaults.linkheader_missing_modules()
prettyprinting_modules = aiocoap.defaults.prettyprint_missing_modules()

AIOCOAP_CLIENT = PYTHON_PREFIX + ["./aiocoap-client"]
AIOCOAP_RD = PYTHON_PREFIX + ["./aiocoap-rd"]


async def check_output(*args, **kwargs):
    return (await check_both(*args, **kwargs))[0]


async def check_stderr(*args, **kwargs):
    return (await check_both(*args, **kwargs))[1]


async def check_both(
    args, *, stdin_buffer=None, stderr=subprocess.PIPE, env=None, expected_returncode=0
):
    proc = await asyncio.create_subprocess_exec(
        *args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, env=env
    )
    (stdout, stderr) = await proc.communicate(stdin_buffer)
    if proc.returncode != expected_returncode:
        raise subprocess.CalledProcessError(
            cmd=args, returncode=proc.returncode, output=stdout, stderr=stderr
        )
    return (stdout, stderr)


class TestCommandlineClient(WithTestServer):
    @no_warnings
    async def test_help(self):
        # CI environments often don't have any locale set. That's not
        # representative of the interactive environments that run --help
        # (though it may be for others). Setting C.UTF-8 because at least pypy3
        # 7.3 doesn't default to a UTF-8 enabled mode, and the help output is
        # not just ASCII.
        helptext = await check_output(
            AIOCOAP_CLIENT + ["--help"], env={"LANG": "C.UTF-8"}
        )
        # We can't test for "usage: aiocoap-client" because starting 3.14,
        # output is colored.
        self.assertTrue(
            b"usage:" in helptext
            and b"Content format of the --payload data." in helptext
        )

    @no_warnings
    async def test_get(self):
        empty_default = await check_output(
            AIOCOAP_CLIENT + ["coap://" + self.servernetloc + "/empty"]
        )
        self.assertEqual(empty_default, b"")

        empty_json = await check_output(
            AIOCOAP_CLIENT
            + [
                "coap://" + self.servernetloc + "/empty",
                "--accept",
                "application/json",
                "--quiet",
            ]
        )
        self.assertEqual(empty_json, b"{}")

        verbose = await check_output(
            AIOCOAP_CLIENT + ["coap://" + self.servernetloc + "/empty", "-vv"],
            stderr=subprocess.STDOUT,
        )
        verbose = verbose.decode("utf-8").strip().split("\n")
        # Filtering out regular `-v` output, which is intended for users.
        info_from_cli = [l for l in verbose if ":coap.aiocoap-client:" in l]
        info_from_library = [l for l in verbose if l not in info_from_cli]
        # It'd not be actually wrong to have info level messages in here, but
        # they should at least not start appearing unnoticed.
        self.assertEqual(
            info_from_library, [], "Unexpected info-level messages in simple request"
        )
        # Precise format may vary
        self.assertTrue(
            any("Uri-Path (11): 'empty'" in l for l in info_from_cli),
            f"-v should include human-redable form of request (but is just {info_from_cli})",
        )

        debug = await check_output(
            AIOCOAP_CLIENT
            + [
                "coap://" + self.servernetloc + "/empty",
                "-v",
                "-v",
                "-v",
                "--no-color",
            ],
            stderr=subprocess.STDOUT,
        )
        self.assertTrue(
            b"DEBUG:coap:Incoming message" in debug,
            "Not even some (or unexpected) output in aiocoap-client -vvv",
        )

        quiet = await check_output(
            AIOCOAP_CLIENT + ["coap://" + self.servernetloc + "/empty", "--quiet"],
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(quiet, b"")

        explicit_code = await check_output(
            AIOCOAP_CLIENT + ["coap://" + self.servernetloc + "/empty", "-m1"]
        )
        self.assertEqual(explicit_code, b"")

        if not prettyprinting_modules:
            json_formatted = await check_output(
                AIOCOAP_CLIENT
                + [
                    "coap://" + self.servernetloc + "/answer",
                    "--accept",
                    "application/json",
                    "--pretty-print",
                ]
            )
            # Concrete formatting may vary, but it should be indented
            self.assertEqual(
                json_formatted.replace(b"\r", b""), b'{\n    "answer": 42\n}'
            )

            json_colorformatted = await check_output(
                AIOCOAP_CLIENT
                + [
                    "coap://" + self.servernetloc + "/answer",
                    "--accept",
                    "application/json",
                    "--pretty-print",
                    "--color",
                ]
            )
            self.assertTrue(
                b"\x1b[" in json_colorformatted,
                "No color indication in pretty-printed JSON",
            )
            self.assertTrue(
                b"    " in json_colorformatted,
                "No indentation in color-pretty-printed JSON",
            )

            json_coloronly = await check_output(
                AIOCOAP_CLIENT
                + [
                    "coap://" + self.servernetloc + "/answer",
                    "--accept",
                    "application/json",
                    "--color",
                ]
            )
            self.assertTrue(
                b"\x1b[" in json_coloronly, "No color indication in color-printed JSON"
            )
            self.assertTrue(
                b"    " not in json_coloronly, "Indentation in color-printed JSON"
            )

            cbor_formatted = await check_output(
                AIOCOAP_CLIENT
                + [
                    "coap://" + self.servernetloc + "/answer",
                    "--accept",
                    "application/cbor",
                    "--pretty-print",
                ]
            )
            # Concrete formatting depends on cbor-diag package
            self.assertEqual(cbor_formatted, b'{"answer": 42}')

    @no_warnings
    async def test_post(self):
        replace_foo = await check_output(
            AIOCOAP_CLIENT
            + [
                "coap://" + self.servernetloc + "/replacing/one",
                "-m",
                "post",
                "--payload",
                "f00",
            ]
        )
        self.assertEqual(replace_foo, b"fOO")

        replace_file = await check_output(
            AIOCOAP_CLIENT
            + [
                "coap://" + self.servernetloc + "/replacing/one",
                "-m",
                "post",
                "--payload",
                "@" + os.devnull,
            ]
        )
        self.assertEqual(replace_file, b"")

    @unittest.skipIf(
        prettyprinting_modules,
        "Modules missing for running pretty-printing tests: %s"
        % (prettyprinting_modules,),
    )
    @no_warnings
    async def test_pretty_post(self):
        # POSTing CBOR is very risky, but it works for this value and allows
        # testing, in one go, the parsing of payload based on content-format,
        # and the rendering of output based on the Accept
        replace_cbor = await check_output(
            AIOCOAP_CLIENT
            + [
                "coap://" + self.servernetloc + "/replacing/one",
                "-m",
                "post",
                "--content-format",
                "application/cbor",
                "--accept",
                "application/octet-stream",
                "--pretty-print",
                "--payload",
                '["f00"]',
            ]
        )
        self.assertEqual(
            replace_cbor,
            b"00000000  81 63 66 4f 4f                                    |.cfOO|\n00000005\n",
        )

    @no_warnings
    async def test_location(self):
        diagnostic_post = await check_output(
            AIOCOAP_CLIENT
            + [
                "coap://" + self.servernetloc + "/create/",
                "-m",
                "post",
            ],
            stderr=subprocess.STDOUT,
        )
        # Or similar; what matters is that the URI is properly recomposed
        self.assertEqual(
            b"Location options indicate new resource: /create/here/?this=this&that=that\n",
            diagnostic_post,
        )

    @no_warnings
    async def test_interactive(self):
        interactive_out = await check_output(
            AIOCOAP_CLIENT
            + [
                "--interactive",
            ],
            stdin_buffer=f"coap://{self.servernetloc}/create/ -m post\ncoap://{self.servernetloc}/empty\n".encode(
                "utf8"
            ),
            stderr=subprocess.STDOUT,
        )
        # Or similar, point is it should be plausible
        self.assertEqual(
            b"aiocoap> Location options indicate new resource: /create/here/?this=this&that=that\naiocoap> aiocoap> ",
            interactive_out,
        )

    @no_warnings
    async def test_erroneous(self):
        with self.assertRaises(subprocess.CalledProcessError):
            # non-existent method
            await check_output(
                AIOCOAP_CLIENT + ["coap://" + self.servernetloc + "/empty", "-mSPAM"],
                stderr=subprocess.STDOUT,
            )

        with self.assertRaises(subprocess.CalledProcessError):
            # not a URI
            await check_output(
                AIOCOAP_CLIENT + ["coap::://" + self.servernetloc + "/empty"],
                stderr=subprocess.STDOUT,
            )

        with self.assertRaises(subprocess.CalledProcessError):
            # relative URI
            await check_output(AIOCOAP_CLIENT + ["/empty"], stderr=subprocess.STDOUT)

        with self.assertRaises(subprocess.CalledProcessError):
            # non-existent mime type
            await check_output(
                AIOCOAP_CLIENT
                + ["coap://" + self.servernetloc + "/empty", "--accept", "spam/eggs"],
                stderr=subprocess.STDOUT,
            )

        try:
            # No full URI given
            await check_output(
                AIOCOAP_CLIENT + [self.servernetloc + "/empty"],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            self.assertTrue(
                "URL incomplete: Must start with a scheme." in e.output.decode("utf8")
            )
            # It must also show the extra_help
            self.assertTrue(
                "Most URLs in aiocoap need to be given with a scheme"
                in e.output.decode("utf8")
            )
        else:
            raise AssertionError(
                "Calling aiocoap-client without a full URI should fail."
            )

        try:
            await check_output(
                AIOCOAP_CLIENT + ["http://" + self.servernetloc + "/empty"],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            self.assertTrue(
                "No remote endpoint set for request" in e.output.decode("utf8")
            )
            # Extra help even gives concrete output
            self.assertTrue(
                f"The message is set up for use with a proxy (because the scheme of 'http://{self.servernetloc}/empty' is not supported)"
                in e.output.decode("utf8")
            )
        else:
            raise AssertionError(
                "Calling aiocoap-client without a HTTP URI should fail."
            )

    @no_warnings
    async def test_noproxy(self):
        # Having this successful and just return text is a bespoke weirdness of
        # the /empty resource (and MultiRepresentationResource in general).
        # Once https://github.com/chrysn/aiocoap/issues/268 is resolved, their
        # workarounds that make this not just ignore the critical proxy options
        # in the first place will go away, and this will need to process
        # aiocoap-client failing regularly.
        stdout = await check_output(
            AIOCOAP_CLIENT
            + [
                "coap://0.0.0.0/empty",
                "--proxy",
                "coap://" + self.servernetloc,
            ],
            stderr=subprocess.STDOUT,
        )

        self.assertEqual(stdout, b"This is no proxy")

    @no_warnings
    async def test_blame_broadcast(self):
        # None of the errors have to be verbatim, but the gist should be there.

        stderr = await check_stderr(
            AIOCOAP_CLIENT + ["coap://255.255.255.255"], expected_returncode=1
        )
        self.assertTrue(
            b"For example, this can occur when attempting to send broadcast requests instead of multicast requests."
            in stderr,
            f"Expected error about broadcast traffic but got {stderr!r}",
        )

    @no_warnings
    @unittest.skipIf(
        using_simple6 or in_woodpecker,
        "Error reporting does not work in this situation for unknown reasons",
        # but different reasons for simple6 and woodpecker
    )
    async def test_blame_connectivity_ipv6(self):
        # Conveniently, on Linux this behaves indistinguishable from not having
        # v6 connectivity, and we don't have to create a v4-only test setup.
        stderr = await check_stderr(
            AIOCOAP_CLIENT + ["coap://[64:ff9b::]"], expected_returncode=1
        )
        self.assertTrue(
            b"This may be due to lack of IPv6 connectivity" in stderr,
            f"Expected error about IPv6 connectivity but got {stderr!r}",
        )

    @no_warnings
    @unittest.skipIf(
        using_simple6 or in_woodpecker,
        "Error reporting does not work in this situation for unknown reasons",
        # but different reasons for simple6 and woodpecker
    )
    async def test_blame_connectivity_ipv4(self):
        # Conveniently, on Linux this behaves indistinguishable from not having
        # v4 connectivity, and we don't have to create a v6-only test setup.
        stderr = await check_stderr(
            AIOCOAP_CLIENT + ["coap://100.64.0.0"], expected_returncode=1
        )
        self.assertTrue(
            b"This may be due to lack of IPv4 connectivity" in stderr,
            f"Expected error about IPv4 connectivity but got {stderr!r}",
        )


class TestCommandlineRD(unittest.TestCase):
    @unittest.skipIf(
        linkheader_modules,
        "Modules missing for running RD tests: %s" % (linkheader_modules,),
    )
    def test_help(self):
        helptext = subprocess.check_output(AIOCOAP_RD + ["--help"])
        self.assertTrue(
            b"usage:" in helptext and b"Compatibility mode for LwM2M" in helptext
        )
