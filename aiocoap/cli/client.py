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
from pathlib import Path

import shlex
# even though not used directly, this has side effects on the input() function
# used in interactive mode
try:
    import readline # noqa: F401
except ImportError:
    pass # that's normal on some platforms, and ok since it's just a usability enhancement

import aiocoap
import aiocoap.defaults
import aiocoap.meta
import aiocoap.proxy.client
from aiocoap.util import contenttype
from aiocoap.util.cli import ActionNoYes
from aiocoap.numbers import media_types

def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--non', help="Send request as non-confirmable (NON) message", action='store_true')
    p.add_argument('-m', '--method', help="Name or number of request method to use (default: %(default)s)", default="GET")
    p.add_argument('--observe', help="Register an observation on the resource", action='store_true')
    p.add_argument('--observe-exec', help="Run the specified program whenever the observed resource changes, feeding the response data to its stdin", metavar='CMD')
    p.add_argument('--accept', help="Content format to request", metavar="MIME")
    p.add_argument('--proxy', help="Relay the CoAP request to a proxy for execution", metavar="HOST[:PORT]")
    p.add_argument('--payload', help="Send X as request payload (eg. with a PUT). If X starts with an '@', its remainder is treated as a file name and read from; '@-' reads from the console. Non-file data may be recoded, see --content-format.", metavar="X")
    p.add_argument('--payload-initial-szx', help="Size exponent to limit the initial block's size (0 ≙ 16 Byte, 6 ≙ 1024 Byte)", metavar="SZX", type=int)
    p.add_argument('--content-format', help="Content format of the --payload data. If a known format is given and --payload has a non-file argument, conversion is attempted (currently only JSON/Python-literals to CBOR).", metavar="MIME")
    p.add_argument('--no-set-hostname', help="Suppress transmission of Uri-Host even if the host name is not an IP literal", dest="set_hostname", action='store_false', default=True)
    p.add_argument('-v', '--verbose', help="Increase the debug output", action="count")
    p.add_argument('-q', '--quiet', help="Decrease the debug output", action="count")
    p.add_argument('--interactive', help="Enter interactive mode", action="store_true") # careful: picked before parsing
    p.add_argument('--credentials', help="Load credentials to use from a given file", type=Path)
    p.add_argument('--version', action="version", version='%(prog)s ' + aiocoap.meta.version)

    p.add_argument('--color',
            help="Color output (default on TTYs if all required modules are installed)",
            default=None,
            action=ActionNoYes,
            )
    p.add_argument('--pretty-print',
            help="Pretty-print known content formats (default on TTYs if all required modules are installed)",
            default=None,
            action=ActionNoYes,
            )
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

def colored(text, options, *args, **kwargs):
    """Apply termcolor.colored with the given args if options.color is set"""
    if not options.color:
        return text

    import termcolor
    return termcolor.colored(text, *args, **kwargs)

def incoming_observation(options, response):
    if options.observe_exec:
        p = subprocess.Popen(options.observe_exec, shell=True, stdin=subprocess.PIPE)
        # FIXME this blocks
        p.communicate(response.payload)
    else:
        sys.stdout.write(colored('---', options, 'grey', attrs=['bold']) + '\n')
        if response.code.is_successful():
            present(response, options, file=sys.stderr)
        else:
            sys.stdout.flush()
            print(colored(response.code, options, 'red'), file=sys.stderr)
            if response.payload:
                present(response, options, file=sys.stderr)

def apply_credentials(context, credentials, errfn):
    if credentials.suffix == '.json':
        import json
        context.client_credentials.load_from_dict(json.load(credentials.open('rb')))
    else:
        raise errfn("Unknown suffix: %s (expected: .json)" % (credentials.suffix))

def present(message, options, file=sys.stdout):
    """Write a message payload to the output, pretty printing and/or coloring
    it as configured in the options."""
    if not message.payload:
        return

    payload = None

    mime = media_types.get(message.opt.content_format,
            'application/octet-stream')
    if options.pretty_print:
        from aiocoap.util.prettyprint import pretty_print
        prettyprinted = pretty_print(message)
        if prettyprinted is not None:
            (infos, mime, payload) = prettyprinted
            if not options.quiet:
                for i in infos:
                    print(colored(i, options, 'grey', attrs=['bold']),
                            file=sys.stderr)

    color = options.color
    if color:
        from aiocoap.util.prettyprint import lexer_for_mime
        import pygments
        try:
            lexer = lexer_for_mime(mime)
        except pygments.util.ClassNotFound:
            color = False

    if color and payload is None:
        # Coloring requires a unicode-string style payload, either from the
        # mime type or from the pretty printer.
        try:
            payload = message.payload.decode('utf8')
        except UnicodeDecodeError:
            color = False

    if color:
        from pygments.formatters import TerminalFormatter
        from pygments import highlight
        highlit = highlight(
            payload,
            lexer,
            TerminalFormatter(),
            )
        # The TerminalFormatter already adds an end-of-line character, not
        # trying to add one for any missing trailing newlines.
        print(highlit, file=file, end="")
        file.flush()
    else:
        if payload is None:
            file.buffer.write(message.payload)
            if file.isatty() and message.payload[-1:] != b'\n':
                file.write("\n")
        else:
            file.write(payload)
            if file.isatty() and payload[-1] != '\n':
                file.write("\n")

async def single_request(args, context=None):
    parser = build_parser()
    options = parser.parse_args(args)

    pretty_print_modules = aiocoap.defaults.prettyprint_missing_modules()
    if pretty_print_modules and \
            (options.color is True or options.pretty_print is True):
        parser.error("Color and pretty printing require the following"
                " additional module(s) to be installed: %s" %
                ", ".join(pretty_print_modules))
    if options.color is None:
        options.color = sys.stdout.isatty() and not pretty_print_modules
    if options.pretty_print is None:
        options.pretty_print = sys.stdout.isatty() and not pretty_print_modules

    configure_logging((options.verbose or 0) - (options.quiet or 0))

    try:
        code = getattr(aiocoap.numbers.codes.Code, options.method.upper())
    except AttributeError:
        try:
            code = aiocoap.numbers.codes.Code(int(options.method))
        except ValueError:
            raise parser.error("Unknown method")

    if context is None:
        context = await aiocoap.Context.create_client_context()

    if options.credentials is not None:
        apply_credentials(context, options.credentials, parser.error)

    request = aiocoap.Message(code=code, mtype=aiocoap.NON if options.non else aiocoap.CON)
    try:
        request.set_request_uri(options.url, set_uri_host=options.set_hostname)
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

    if options.content_format:
        try:
            request.opt.content_format = int(options.content_format)
        except ValueError:
            try:
                request.opt.content_format = aiocoap.numbers.media_types_rev[options.content_format]
            except KeyError:
                raise parser.error("Unknown content format")

    if options.payload:
        if options.payload.startswith('@'):
            filename = options.payload[1:]
            if filename == "-":
                f = sys.stdin.buffer
            else:
                f = open(filename, 'rb')
            try:
                request.payload = f.read()
            except OSError as e:
                raise parser.error("File could not be opened: %s"%e)
        else:
            if contenttype.categorize(aiocoap.numbers.media_types.get(request.opt.content_format, "")) == 'cbor':
                try:
                    import cbor2 as cbor
                except ImportError as e:
                    raise parser.error("CBOR recoding not available (%s)" % e)
                import json
                try:
                    decoded = json.loads(options.payload)
                except json.JSONDecodeError as e:
                    import ast
                    try:
                        decoded = ast.literal_eval(options.payload)
                    except ValueError:
                        raise parser.error("JSON and Python recoding failed. Make sure quotation marks are escaped from the shell. JSON error: %s" % e)
                request.payload = cbor.dumps(decoded)
            else:
                request.payload = options.payload.encode('utf8')

    if options.payload_initial_szx is not None:
        request.opt.block1 = aiocoap.optiontypes.BlockOption.BlockwiseTuple(
                0,
                False,
                options.payload_initial_szx,
            )

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
            response_data = await requester.response
        except aiocoap.error.ResolutionError as e:
            print("Name resolution error:", e, file=sys.stderr)
            sys.exit(1)
        except aiocoap.error.NetworkError as e:
            print("Network error:", e, file=sys.stderr)
            sys.exit(1)
        # Fallback while not all backends raise NetworkErrors
        except OSError as e:
            text = str(e)
            if not text:
                text = repr(e)
            if not text:
                # eg ConnectionResetError flying out of a misconfigured SSL server
                text = type(e)
            print("Error:", text, file=sys.stderr)
            sys.exit(1)

        if response_data.code.is_successful():
            present(response_data, options)
        else:
            print(colored(response_data.code, options, 'red'), file=sys.stderr)
            present(response_data, options, file=sys.stderr)
            sys.exit(1)

        if options.observe:
            exit_reason = await observation_is_over
            print("Observation is over: %r"%(exit_reason,), file=sys.stderr)
    finally:
        if not requester.response.done():
            requester.response.cancel()
        if options.observe and not requester.observation.cancelled:
            requester.observation.cancel()

interactive_expecting_keyboard_interrupt = asyncio.Future()

async def interactive():
    global interactive_expecting_keyboard_interrupt

    context = await aiocoap.Context.create_client_context()

    while True:
        try:
            # when http://bugs.python.org/issue22412 is resolved, use that instead
            line = await asyncio.get_event_loop().run_in_executor(None, lambda: input("aiocoap> "))
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

        done, pending = await asyncio.wait([current_task, interactive_expecting_keyboard_interrupt], return_when=asyncio.FIRST_COMPLETED)

        if current_task not in done:
            current_task.cancel()
        else:
            try:
                await current_task
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

        while not task.done():
            try:
                loop.run_until_complete(task)
            except KeyboardInterrupt:
                if not interactive_expecting_keyboard_interrupt.done():
                    interactive_expecting_keyboard_interrupt.set_result(None)
            except SystemExit:
                continue # asyncio/tasks.py(242) raises those after setting them as results, but we particularly want them back in the loop

if __name__ == "__main__":
    sync_main()
