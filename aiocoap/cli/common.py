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
functionality.

Typical use is like this::

>>> p = argparse.ArgumentParser()
>>> p.add_argument('--foo')                         # doctest: +ELLIPSIS
_...
>>> add_server_arguments(p)
>>> opts = p.parse_args(['--bind', '[::1]:56830', '--foo=bar'])

You can then either pass opts directly to
:func:`server_context_from_arguments`, or split up the arguments::

>>> server_opts = extract_server_arguments(opts)
>>> opts
Namespace(foo='bar')

Then, server_opts can be passed to `server_context_from_arguments`.
"""

import sys
import argparse
import json
from pathlib import Path

from ..util import hostportsplit
from ..protocol import Context
from ..credentials import CredentialsMap

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
                "\nIf a port is specified, and (D)TLS support is available, those protocols will be bound to one port higher (as are the default ports, 5683 for CoAP and 5684 for CoAP over (D)TLS)."
                "\n", file=sys.stderr)
        parser.exit()

def add_server_arguments(parser):
    """Add the --bind option to an argparse parser"""

    def hostportsplit_helper(arg):
        """Wrapper around hostportsplit that gives better error messages than
        'invalid hostportsplit value'"""

        try:
            return hostportsplit(arg)
        except ValueError:
            raise parser.error("Invalid argument to --bind." +
                    " Did you mean --bind '[%s]'?" % arg
                    if arg.count(':') >= 2 and '[' not in arg
                    else " See --help-bind for details.")

    parser.add_argument('--bind', help="Host and/or port to bind to (see --help-bind for details)", type=hostportsplit_helper, default=None)

    parser.add_argument('--credentials', help="JSON file pointing to credentials for the server's identity/ies.", type=Path)

    # These are to be eventually migrated into credentials
    parser.add_argument('--tls-server-certificate', help="TLS certificate (chain) to present to connecting clients (in PEM format)", metavar="CRT")
    parser.add_argument('--tls-server-key', help="TLS key to load that supports the server certificate", metavar="KEY")

    parser.add_argument('--help-bind', help=argparse.SUPPRESS, action=_HelpBind)

def extract_server_arguments(namespace):
    """Given the output of .parse() on a ArgumentParser that had
    add_server_arguments called with it, remove the resulting option in-place
    from namespace and return them in a separate namespace."""

    server_arguments = type(namespace)()
    server_arguments.bind = namespace.bind
    server_arguments.tls_server_certificate = namespace.tls_server_certificate
    server_arguments.tls_server_key = namespace.tls_server_key
    server_arguments.credentials = namespace.credentials

    del namespace.bind
    del namespace.tls_server_certificate
    del namespace.tls_server_key
    del namespace.credentials
    del namespace.help_bind

    return server_arguments

async def server_context_from_arguments(site, namespace, **kwargs):
    """Create a bound context like
    :meth:`.aiocoap.Context.create_server_context`, but take the bind and TLS
    settings from a namespace returned from an argparse parser that has had
    :func:`add_server_arguments` run on it.
    """

    if namespace.tls_server_certificate:
        import ssl

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=namespace.tls_server_certificate, keyfile=namespace.tls_server_key)
        ssl_context.set_alpn_protocols(["coap"])
        if hasattr(ssl_context, 'sni_callback'): # starting python 3.7
            ssl_context.sni_callback = lambda obj, name, context: setattr(obj, "indicated_server_name", name)
    else:
        ssl_context = None

    if namespace.credentials:
        server_credentials = CredentialsMap()
        server_credentials.load_from_dict(json.load(namespace.credentials.open('rb')))

        # FIXME: could be non-OSCORE as well -- can we build oscore_sitewrapper
        # in such a way it only depends on the OSCORE dependencies if there are
        # actual identities present?
        from aiocoap.oscore_sitewrapper import OscoreSiteWrapper
        site = OscoreSiteWrapper(site, server_credentials)

    return await Context.create_server_context(site, namespace.bind, _ssl_context=ssl_context, **kwargs)
