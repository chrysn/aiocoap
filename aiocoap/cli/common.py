#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Common options of aiocoap command line utilities

Unlike those in :mod:`aiocoap.util.cli`, these are particular to aiocoap
functionality."""

import sys
import argparse

from ..util import hostportsplit

class _HelpBind(argparse.Action):
    def __init__(self, *args, **kwargs):
        kwargs['nargs'] = 0
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print("The --bind option can take either of the following formats:"
                "\n    :port -- bind to a given port on all available interfaces"
                "\n    host -- bind to default ports on a given host name (can also be an IP address; IPv6 addresses need to be in square brackets)"
                "\n    host:port -- bind only to a specific port on a given host"
                "\n\nBy default, the server will bind to all available addressess and protocols on the respective default ports."
                "\nIf a port is specified, and (D)TLS support is available, starting a server is likely to fail."
                "\n", file=sys.stderr)
        parser.exit()

def add_server_arguments(parser):
    """Add the --bind option to an argparse parser"""

    parser.add_argument('--bind', help="Host and/or port to bind to (see --help-bind for details)", type=hostportsplit, default=None)

    parser.add_argument('--help-bind', help=argparse.SUPPRESS, action=_HelpBind)
