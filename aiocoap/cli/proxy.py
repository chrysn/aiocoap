# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""a plain CoAP proxy that can work both as forward and as reverse proxy"""

import sys
import logging
import asyncio
import argparse

import aiocoap
from aiocoap.proxy.server import ForwardProxyWithPooledObservations, ReverseProxyWithPooledObservations, NameBasedVirtualHost, SubresourceVirtualHost, UnconditionalRedirector

def parse_commandline(args):
    p = argparse.ArgumentParser(description=__doc__)

    mode = p.add_argument_group("mode", "Required argument for setting the operation mode")
    mode.add_argument('--forward', help="Run as forward proxy", action='store_const', const=ForwardProxyWithPooledObservations, dest='direction')
    mode.add_argument('--reverse', help="Run as reverse proxy", action='store_const', const=ReverseProxyWithPooledObservations, dest='direction')

    details = p.add_argument_group("details", "Options that govern how requests go in and out")
    details.add_argument('--server-address', help="Address to bind the server context to", metavar="HOST", default="::")
    details.add_argument('--server-port', help="Port to bind the server context to", metavar="PORT", default=aiocoap.COAP_PORT, type=int)
    details.add_argument('--proxy', help="Relay outgoing requests through yet another proxy", metavar="HOST[:PORT]")
    r = p.add_argument_group('Rules', description="Sequence of forwarding rules that, if matched by a request, specify a forwarding destination")
    class TypedAppend(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, self.dest) is None:
                setattr(namespace, self.dest, [])
            getattr(namespace, self.dest).append((option_string, values))
    r.add_argument('--namebased', help="If Uri-Host matches NAME, route to DEST", metavar="NAME:DEST", action=TypedAppend, dest='r')
    r.add_argument('--pathbased', help="If a requested path starts with PATH, split that part off and route to DEST", metavar="PATH:DEST", action=TypedAppend, dest='r')
    r.add_argument('--unconditional', help="Route all requests not previously matched to DEST", metavar="DEST", action=TypedAppend, dest='r')

    return p, p.parse_args(args)

class Main:
    def __init__(self, args):
        self.args = args
        self.initializing = asyncio.Task(self.__start())

    @asyncio.coroutine
    def __start(self):
        parser, options = parse_commandline(self.args)

        if options.direction is None:
            raise parser.error("Either --forward or --reverse must be given.")

        self.outgoing_context = yield from aiocoap.Context.create_client_context(dump_to='/tmp/proxy-out.log')
        proxy = options.direction(self.outgoing_context)
        for kind, data in options.r or ():
            if kind == '--namebased':
                try:
                    name, dest = data.split(':', 1)
                except:
                    raise parser.error("--namebased needs NAME:DEST as arguments")
                r = NameBasedVirtualHost(name, dest)
            elif kind == '--pathbased':
                try:
                    path, dest = data.split(':', 1)
                except:
                    raise parser.error("--pathbased needs PATH:DEST as arguments")
                r = SubresourceVirtualHost(path.split('/'), dest)
            elif kind == '--unconditional':
                r = UnconditionalRedirector(data)
            else:
                raise AssertionError('Unknown redirectory kind')
            proxy.add_redirector(r)

        self.proxy_context = yield from aiocoap.Context.create_server_context(proxy, dump_to='/tmp/proxy-in.log', bind=(options.server_address, options.server_port))

    @asyncio.coroutine
    def shutdown(self):
        yield from self.initializing

        yield from self.outgoing_context.shutdown()
        yield from self.proxy_context.shutdown()

def sync_main(args=None):
    if args is None:
        args = sys.argv[1:]
    logging.basicConfig(level=logging.DEBUG)
    main = None
    try:
        loop = asyncio.get_event_loop()
        main = Main(args)
        loop.run_until_complete(main.initializing)
        logging.info("proxy ready")
        loop.run_forever()
    except KeyboardInterrupt:
        sys.exit(3)
    finally:
        print("stopping loop")
        if main is not None:
            loop.run_until_complete(main.shutdown())
        loop.stop()

if __name__ == "__main__":
    # if you want to run this using `python3 -m`, see http://bugs.python.org/issue22480
    sync_main()
