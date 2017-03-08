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

# FIXME: set the subprocesses up in a way the too can measure coverage if
# coverage is currently being measured

import sys
import subprocess
import asyncio

import aiocoap

from .test_server import WithTestServer, no_warnings
from . import test_server

AIOCOAP_CLIENT = ['./aiocoap-client']
if 'coverage' in sys.modules:
    AIOCOAP_CLIENT = ['python3', '-m', 'coverage', 'run', '--parallel-mode'] + AIOCOAP_CLIENT

class TestCommandlineClient(WithTestServer):
    @no_warnings
    def test_help(self):
        helptext = subprocess.check_output(AIOCOAP_CLIENT + ['--help'])
        self.assertTrue(helptext.startswith(b'usage: aiocoap-client '))

    @no_warnings
    def test_get(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(loop.run_in_executor(None, self._test_get))

    def _test_get(self):
        empty_default = subprocess.check_output(AIOCOAP_CLIENT + ['coap://' + self.servernetloc + '/empty'])
        self.assertEqual(empty_default, b'')

        empty_json = subprocess.check_output(AIOCOAP_CLIENT + ['coap://' + self.servernetloc + '/empty', '--accept', 'application/json', '--quiet'])
        self.assertEqual(empty_json, b'{}')
