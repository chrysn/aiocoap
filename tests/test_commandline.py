# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This tests launch the command line utility aiocoap-client in a sub-process.

The aiocoap-proxy utility is tested in test_proxy inside this process as
orchestration of success reporting is not that easy with a daemon process;
aiocoap-rd might need to get tested in a similar way to -proxy."""

import subprocess
import asyncio
import unittest

import aiocoap.defaults

from .test_server import WithTestServer, no_warnings, asynctest
from .common import PYTHON_PREFIX

linkheader_modules = aiocoap.defaults.linkheader_missing_modules()

AIOCOAP_CLIENT = PYTHON_PREFIX + ['./aiocoap-client']
AIOCOAP_RD = PYTHON_PREFIX + ['./aiocoap-rd']

class TestCommandlineClient(WithTestServer):
    @no_warnings
    def test_help(self):
        helptext = subprocess.check_output(AIOCOAP_CLIENT + ['--help'])
        self.assertTrue(helptext.startswith(b'usage: aiocoap-client '))

    @no_warnings
    @asynctest
    async def test_get(self):
        await self.loop.run_in_executor(None, self._test_get)

    def _test_get(self):
        # FIXME style: subprocesses could be orchestrated using asyncio as well
        empty_default = subprocess.check_output(AIOCOAP_CLIENT + ['coap://' + self.servernetloc + '/empty'])
        self.assertEqual(empty_default, b'')

        empty_json = subprocess.check_output(AIOCOAP_CLIENT + ['coap://' + self.servernetloc + '/empty', '--accept', 'application/json', '--quiet'])
        self.assertEqual(empty_json, b'{}')

        verbose = subprocess.check_output(AIOCOAP_CLIENT + [
            'coap://' + self.servernetloc + '/empty', '-v'],
            stderr=subprocess.STDOUT)
        # It'd not be actually wrong to have info level messages in here, but
        # they should at least not start appearing unnoticed.
        self.assertEqual(verbose, b'',
                "Unexpected info-level messages in simple request")

        debug = subprocess.check_output(AIOCOAP_CLIENT + [
            'coap://' + self.servernetloc + '/empty', '-v', '-v'],
            stderr=subprocess.STDOUT)
        self.assertTrue(b'DEBUG:coap:Incoming message' in debug,
                "Not even some (or unexpected) output in aiocoap-client -vv")

        quiet = subprocess.check_output(AIOCOAP_CLIENT + [
            'coap://' + self.servernetloc + '/empty', '--quiet'],
            stderr=subprocess.STDOUT)
        self.assertEqual(quiet, b'')

        explicit_code = subprocess.check_output(AIOCOAP_CLIENT + [
            'coap://' + self.servernetloc + '/empty', '-m1'])
        self.assertEqual(explicit_code, b'')

    @no_warnings
    @asynctest
    async def test_post(self):
        await self.loop.run_in_executor(None, self._test_post)

    def _test_post(self):
        replace_foo = subprocess.check_output(AIOCOAP_CLIENT + [
            'coap://' + self.servernetloc + '/replacing/one',
            '-m', 'post', '--payload', 'f00'
            ])
        self.assertEqual(replace_foo, b'fOO')

        replace_file = subprocess.check_output(AIOCOAP_CLIENT + [
            'coap://' + self.servernetloc + '/replacing/one',
            '-m', 'post', '--payload', '@/dev/null'
            ])
        self.assertEqual(replace_file, b'')

    @no_warnings
    @asynctest
    async def test_erroneous(self):
        await self.loop.run_in_executor(None, self._test_erroneous)

    def _test_erroneous(self):
        with self.assertRaises(subprocess.CalledProcessError):
            # non-existant method
            subprocess.check_output(AIOCOAP_CLIENT + [
                'coap://' + self.servernetloc + '/empty', '-mSPAM'],
                stderr=subprocess.STDOUT)

        with self.assertRaises(subprocess.CalledProcessError):
            # not a URI
            subprocess.check_output(AIOCOAP_CLIENT + [
                'coap::://' + self.servernetloc + '/empty'],
                stderr=subprocess.STDOUT)

        with self.assertRaises(subprocess.CalledProcessError):
            # relative URI
            subprocess.check_output(AIOCOAP_CLIENT + [
                '/empty'],
                stderr=subprocess.STDOUT)

        with self.assertRaises(subprocess.CalledProcessError):
            # non-existant mime type
            subprocess.check_output(AIOCOAP_CLIENT + [
                'coap://' + self.servernetloc + '/empty', '--accept', 'spam/eggs'],
                stderr=subprocess.STDOUT)

class TestCommandlineRD(unittest.TestCase):
    @unittest.skipIf(linkheader_modules, "Modules missing for running RD tests: %s"%(linkheader_modules,))
    def test_help(self):
        helptext = subprocess.check_output(AIOCOAP_RD + ['--help'])
        self.assertTrue(helptext.startswith(b'usage: aiocoap-rd '))
