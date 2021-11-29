# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""a plain CoAP proxy that can work both as forward and as reverse proxy"""

import sys
import argparse

import aiocoap
from aiocoap.proxy.server import ForwardProxyWithPooledObservations, ProxyWithPooledObservations, NameBasedVirtualHost, SubdomainVirtualHost, SubresourceVirtualHost, UnconditionalRedirector
from aiocoap.util.cli import AsyncCLIDaemon
from aiocoap.cli.common import add_server_arguments, server_context_from_arguments

def build_parser():
    p = argparse.ArgumentParser(description=__doc__)

    mode = p.add_argument_group("mode", "Required argument for setting the operation mode")
    mode.add_argument('--forward', help="Run as forward proxy", action='store_true')
    mode.add_argument('--reverse', help="Run as reverse proxy", action='store_true')

    details = p.add_argument_group("details", "Options that govern how requests go in and out")
    add_server_arguments(details)
    details.add_argument("--register", help="Register with a Resource directory", metavar='RD-URI', nargs='?', default=False)
    details.add_argument("--register-as", help="Endpoint name (with possibly a domain after a dot) to register as", metavar='EP[.D]', default=None)
    details.add_argument("--register-proxy", help="Ask the RD to serve as a reverse proxy. Note that this is only practical for --unconditional or --pathbased reverse proxies.", action='store_true')

    r = p.add_argument_group('Rules', description="Sequence of forwarding rules "
            "that, if matched by a request, specify a forwarding destination. Destinations can be prefixed to change their behavior: With an '@' sign, they are treated as forward proxies. With a '!' sign, the destination is set as Uri-Host.")
    class TypedAppend(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, self.dest) is None:
                setattr(namespace, self.dest, [])
            getattr(namespace, self.dest).append((option_string, values))
    r.add_argument('--namebased', help="If Uri-Host matches NAME, route to DEST", metavar="NAME:DEST", action=TypedAppend, dest='r')
    r.add_argument('--subdomainbased', help="If Uri-Host is anything.NAME, route to DEST", metavar="NAME:DEST", action=TypedAppend, dest='r')
    r.add_argument('--pathbased', help="If a requested path starts with PATH, split that part off and route to DEST", metavar="PATH:DEST", action=TypedAppend, dest='r')
    r.add_argument('--unconditional', help="Route all requests not previously matched to DEST", metavar="DEST", action=TypedAppend, dest='r')

    return p

def destsplit(dest):
    use_as_proxy = False
    rewrite_uri_host = False
    if dest.startswith('!'):
        dest = dest[1:]
        rewrite_uri_host = True
    if dest.startswith('@'):
        dest = dest[1:]
        use_as_proxy = True
    return dest, rewrite_uri_host, use_as_proxy

class Main(AsyncCLIDaemon):
    async def start(self, args=None):
        parser = build_parser()
        options = parser.parse_args(args if args is not None else sys.argv[1:])
        self.options = options

        if not options.forward and not options.reverse:
            raise parser.error("At least one of --forward and --reverse must be given.")

        self.outgoing_context = await aiocoap.Context.create_client_context()
        if options.forward:
            proxy = ForwardProxyWithPooledObservations(self.outgoing_context)
        else:
            proxy = ProxyWithPooledObservations(self.outgoing_context)
        for kind, data in options.r or ():
            if kind in ('--namebased', '--subdomainbased'):
                try:
                    name, dest = data.split(':', 1)
                except Exception:
                    raise parser.error("%s needs NAME:DEST as arguments" % kind)
                dest, rewrite_uri_host, use_as_proxy = destsplit(dest)
                if rewrite_uri_host and kind == '--subdomainbased':
                    parser.error("The flag '!' makes no sense for subdomain based redirection as the subdomain data would be lost")
                r = (NameBasedVirtualHost if kind == '--namebased' else SubdomainVirtualHost)(name, dest, rewrite_uri_host, use_as_proxy)
            elif kind == '--pathbased':
                try:
                    path, dest = data.split(':', 1)
                except Exception:
                    raise parser.error("--pathbased needs PATH:DEST as arguments")
                r = SubresourceVirtualHost(path.split('/'), dest)
            elif kind == '--unconditional':
                dest, rewrite_uri_host, use_as_proxy = destsplit(data)
                if rewrite_uri_host:
                    parser.error("The flag '!' makes no sense for unconditional redirection as the host name data would be lost")
                r = UnconditionalRedirector(dest, use_as_proxy)
            else:
                raise AssertionError('Unknown redirectory kind')
            proxy.add_redirector(r)

        self.proxy_context = await server_context_from_arguments(proxy, options)

        if options.register is not False:
            from aiocoap.resourcedirectory.client.register import Registerer

            params = {}
            if options.register_as:
                ep, _, d = options.register_as.partition('.')
                params['ep'] = ep
                if d:
                    params['d'] = d
            if options.register_proxy:
                # FIXME: Check this in discovery
                params['proxy'] = 'on'
            # FIXME: Construct this from settings (path-based), and forward results
            proxy.get_resources_as_linkheader = lambda: ""
            self.registerer = Registerer(self.proxy_context, rd=options.register, lt=60,
                    registration_parameters=params)

    async def shutdown(self):
        if self.options.register is not False:
            await self.registerer.shutdown()
        await self.outgoing_context.shutdown()
        await self.proxy_context.shutdown()

sync_main = Main.sync_main

if __name__ == "__main__":
    # if you want to run this using `python3 -m`, see http://bugs.python.org/issue22480
    sync_main()
