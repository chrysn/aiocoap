# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""aiocoap-client is a simple command-line tool for interacting with CoAP servers"""

import sys
import asyncio
import argparse
import logging
import subprocess
import socket

import shlex
# even though not used directly, this has side effects on the input() function
# used in interactive mode
try:
    import readline
except ImportError:
    pass # that's normal on some platforms, and ok since it's just a usability enhancement

import aiocoap
import aiocoap.proxy.client

def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--non', help="Send request as non-confirmable (NON) message", action='store_true')
    p.add_argument('-m', '--method', help="Name or number of request method to use (default: %(default)s)", default="GET")
    p.add_argument('--observe', help="Register an observation on the resource", action='store_true')
    p.add_argument('--observe-exec', help="Run the specified program whenever the observed resource changes, feeding the response data to its stdin", metavar='CMD')
    p.add_argument('--accept', help="Content format to request", metavar="MIME")
    p.add_argument('--proxy', help="Relay the CoAP request to a proxy for execution", metavar="HOST[:PORT]")
    p.add_argument('--payload', help="Send X as payload in POST or PUT requests. If X starts with an '@', its remainder is treated as a file name and read from.", metavar="X")
    p.add_argument('--content-format', help="Content format sent via POST or PUT", metavar="MIME")
    p.add_argument('-v', '--verbose', help="Increase the debug output", action="count")
    p.add_argument('-q', '--quiet', help="Decrease the debug output", action="count")
    p.add_argument('--dump', help="Log network traffic to FILE", metavar="FILE")
    p.add_argument('--interactive', help="Enter interactive mode", action="store_true") # careful: picked before parsing
    p.add_argument('url', help="CoAP address to fetch")

    return p

def configure_logging(verbosity):
    logging.basicConfig()

    if verbosity <= -2:
        logging.getLogger('coap').setLevel(logging.CRITICAL + 1)
    elif verbosity == -1:
        logging.getLogger('coap').setLevel(logging.ERROR)
    elif verbosity == 0:
        logging.getLogger('coap').setLevel(logging.WARNING)
    elif verbosity == 1:
        logging.getLogger('coap').setLevel(logging.INFO)
    elif verbosity >= 2:
        logging.getLogger('coap').setLevel(logging.DEBUG)

def incoming_observation(options, response):
    if options.observe_exec:
        p = subprocess.Popen(options.observe_exec, shell=True, stdin=subprocess.PIPE)
        # FIXME this blocks
        p.communicate(response.payload)
    else:
        sys.stdout.buffer.write(b'---\n')
        if response.code.is_successful():
            sys.stdout.buffer.write(response.payload + (b'\n' if not response.payload.endswith(b'\n') else b''))
            sys.stdout.buffer.flush()
        else:
            print(response.code, file=sys.stderr)
            if response.payload:
                print(response.payload.decode('utf-8'), file=sys.stderr)

@asyncio.coroutine
def single_request(args, context=None):
    parser = build_parser()
    options = parser.parse_args(args)

    configure_logging((options.verbose or 0) - (options.quiet or 0))

    try:
        code = getattr(aiocoap.numbers.codes.Code, options.method.upper())
    except AttributeError:
        try:
            code = aiocoap.numbers.codes.Code(int(options.method))
        except ValueError:
            raise parser.error("Unknown method")

    if context is None:
        context = yield from aiocoap.Context.create_client_context(dump_to=options.dump)
    else:
        if options.dump:
            print("The --dump option is not implemented in interactive mode.", file=sys.stderr)

    request = aiocoap.Message(code=code, mtype=aiocoap.NON if options.non else aiocoap.CON)
    try:
        request.set_request_uri(options.url)
    except ValueError as e:
        raise parser.error(e)

    if not request.opt.uri_host and not request.unresolved_remote:
        raise parser.error("Request URLs need to be absolute.")

    if options.accept:
        try:
            request.opt.accept = int(options.accept)
        except ValueError:
            try:
                request.opt.accept = aiocoap.numbers.media_types_rev[options.accept]
            except KeyError:
                raise parser.error("Unknown accept type")

    if options.observe:
        request.opt.observe = 0
        observation_is_over = asyncio.Future()

    if options.payload:
        if options.payload.startswith('@'):
            try:
                request.payload = open(options.payload[1:], 'rb').read()
            except OSError as e:
                raise parser.error("File could not be opened: %s"%e)
        else:
            request.payload = options.payload.encode('utf8')

    if options.content_format:
        try:
            request.opt.content_format = int(options.content_format)
        except ValueError:
            try:
                request.opt.content_format = aiocoap.numbers.media_types_rev[options.content_format]
            except KeyError:
                raise parser.error("Unknown content format")


    if options.proxy is None:
        interface = context
    else:
        interface = aiocoap.proxy.client.ProxyForwarder(options.proxy, context)

    try:
        requester = interface.request(request)

        if options.observe:
            requester.observation.register_errback(observation_is_over.set_result)
            requester.observation.register_callback(lambda data, options=options: incoming_observation(options, data))

        try:
            response_data = yield from requester.response
        except socket.gaierror as  e:
            print("Name resolution error:", e, file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print("Error:", e, file=sys.stderr)
            sys.exit(1)

        if response_data.code.is_successful():
            sys.stdout.buffer.write(response_data.payload)
            sys.stdout.buffer.flush()
            if response_data.payload and not response_data.payload.endswith(b'\n') and not options.quiet:
                sys.stderr.write('\n(No newline at end of message)\n')
        else:
            print(response_data.code, file=sys.stderr)
            if response_data.payload:
                print(response_data.payload.decode('utf-8'), file=sys.stderr)
            sys.exit(1)

        if options.observe:
            exit_reason = yield from observation_is_over
            print("Observation is over: %r"%(exit_reason,), file=sys.stderr)
    finally:
        if not requester.response.done():
            requester.response.cancel()
        if options.observe and not requester.observation.cancelled:
            requester.observation.cancel()

interactive_expecting_keyboard_interrupt = asyncio.Future()

@asyncio.coroutine
def interactive():
    global interactive_expecting_keyboard_interrupt

    context = yield from aiocoap.Context.create_client_context()

    while True:
        try:
            # when http://bugs.python.org/issue22412 is resolved, use that instead
            line = yield from asyncio.get_event_loop().run_in_executor(None, lambda: input("aiocoap> "))
        except EOFError:
            line = "exit"
        line = shlex.split(line)
        if not line:
            continue
        if line in (["help"], ["?"]):
            line = ["--help"]
        if line in (["quit"], ["q"], ["exit"]):
            return

        current_task = asyncio.Task(single_request(line, context=context))
        interactive_expecting_keyboard_interrupt = asyncio.Future()

        done, pending = yield from asyncio.wait([current_task, interactive_expecting_keyboard_interrupt], return_when=asyncio.FIRST_COMPLETED)

        if current_task not in done:
            current_task.cancel()
        else:
            try:
                yield from current_task
            except SystemExit as e:
                if e.code != 0:
                    print("Exit code: %d"%e.code, file=sys.stderr)
                continue
            except Exception as e:
                print("Unhandled exception raised: %s"%(e,))

def sync_main(args=None):
    # interactive mode is a little messy, that's why this is not using aiocoap.util.cli yet
    if args is None:
        args = sys.argv[1:]

    if '--interactive' not in args:
        try:
            asyncio.get_event_loop().run_until_complete(single_request(args))
        except KeyboardInterrupt:
                sys.exit(3)
    else:
        if len(args) != 1:
            print("No other arguments must be specified when entering interactive mode", file=sys.stderr)
            sys.exit(1)

        loop = asyncio.get_event_loop()
        task = asyncio.Task(interactive())
        task.add_done_callback(lambda result: loop.stop())

        while not loop.is_closed():
            try:
                loop.run_forever()
            except KeyboardInterrupt:
                if not interactive_expecting_keyboard_interrupt.done():
                    interactive_expecting_keyboard_interrupt.set_result(None)
            except SystemExit:
                continue # asyncio/tasks.py(242) raises those after setting them as results, but we particularly want them back in the loop

if __name__ == "__main__":
    sync_main()
