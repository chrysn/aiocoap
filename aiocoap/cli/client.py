# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""aiocoap-client is a simple command-line tool for interacting with CoAP servers"""

import copy
import sys
import asyncio
import argparse
import logging
import signal
import subprocess
from pathlib import Path

import shlex

# even though not used directly, this has side effects on the input() function
# used in interactive mode
try:
    import readline  # noqa: F401
except ImportError:
    pass  # that's normal on some platforms, and ok since it's just a usability enhancement

import aiocoap
import aiocoap.defaults
import aiocoap.meta
import aiocoap.proxy.client
from aiocoap.util import contenttype
from aiocoap.util.cli import ActionNoYes
from aiocoap.numbers import ContentFormat

log = logging.getLogger("coap.aiocoap-client")


def augment_parser_for_global(p, *, prescreen=False):
    p.add_argument(
        "-v",
        "--verbose",
        help="Increase the debug output",
        action="count",
    )
    p.add_argument(
        "-q",
        "--quiet",
        help="Decrease the debug output",
        action="count",
    )
    p.add_argument(
        "--version", action="version", version="%(prog)s " + aiocoap.meta.version
    )

    p.add_argument(
        "--interactive",
        help="Enter interactive mode. Combine with --help or run `help` interactively to see which options apply where; some can be used globally and overwritten locally.",
        action="store_true",
    )


def augment_parser_for_either(p):
    p.add_argument(
        "--color",
        help="Color output (default on TTYs if all required modules are installed)",
        default=None,
        action=ActionNoYes,
    )
    p.add_argument(
        "--pretty-print",
        help="Pretty-print known content formats (default on TTYs if all required modules are installed)",
        default=None,
        action=ActionNoYes,
    )
    p.add_argument(
        "--proxy", help="Relay the CoAP request to a proxy for execution", metavar="URI"
    )
    p.add_argument(
        "--credentials",
        help="Load credentials to use from a given file",
        type=Path,
    )
    p.add_argument(
        "--no-set-hostname",
        help="Suppress transmission of Uri-Host even if the host name is not an IP literal",
        dest="set_hostname",
        action="store_false",
        default=True,
    )
    p.add_argument(
        "--no-sec",
        # Can be "Send request without any security" once it actually does
        # anything; until then, it's fine as a no-op to not impede changing
        # scripts later.
        help=argparse.SUPPRESS,
        dest="sec",
        action="store_false",
        default=None,
    )


def augment_parser_for_interactive(p, *, prescreen=False):
    p.add_argument(
        "--non",
        help="Send request without reliable transport (e.g. over UDP: as non-confirmable (NON) message)",
        action="store_true",
    )
    p.add_argument(
        "-m",
        "--method",
        help="Name or number of request method to use (default: %(default)s)",
        default="GET",
    )
    p.add_argument(
        "--observe", help="Register an observation on the resource", action="store_true"
    )
    p.add_argument(
        "--observe-exec",
        help="Run the specified program whenever the observed resource changes, feeding the response data to its stdin",
        metavar="CMD",
    )
    p.add_argument(
        "--accept",
        help="Content format to request",
        metavar="MIME",
    )
    p.add_argument(
        "--payload",
        help="Send X as request payload (eg. with a PUT). If X starts with an '@', its remainder is treated as a file name and read from; '@-' reads from the console. Non-file data may be recoded, see --content-format.",
        metavar="X",
    )
    p.add_argument(
        "--payload-initial-szx",
        help="Size exponent to limit the initial block's size (0 ≙ 16 Byte, 6 ≙ 1024 Byte)",
        metavar="SZX",
        type=int,
    )
    p.add_argument(
        "--content-format",
        help="Content format of the --payload data. If a known format is given and --payload has a non-file argument, the payload is converted from CBOR Diagnostic Notation.",
        metavar="MIME",
    )
    p.add_argument(
        "url",
        nargs="?" if prescreen else None,
        help="CoAP address to fetch",
    )


def build_parser(*, use_global=True, use_interactive=True, prescreen=False):
    p = argparse.ArgumentParser(description=__doc__, add_help=not prescreen)
    if prescreen:
        p.add_argument("--help", action="store_true")
    if use_global:
        augment_parser_for_global(p, prescreen=prescreen)
    augment_parser_for_either(p)
    if use_interactive:
        augment_parser_for_interactive(p, prescreen=prescreen)

    return p


def configure_logging(verbosity, color):
    if color is not False:
        try:
            import colorlog
        except ImportError:
            color = False
        else:
            colorlog.basicConfig()
    if not color:
        logging.basicConfig()

    if verbosity <= -2:
        logging.getLogger("coap").setLevel(logging.CRITICAL + 1)
    elif verbosity == -1:
        logging.getLogger("coap").setLevel(logging.ERROR)
    elif verbosity == 0:
        logging.getLogger("coap").setLevel(logging.WARNING)
    elif verbosity == 1:
        logging.getLogger("coap").setLevel(logging.WARNING)
        logging.getLogger("coap.aiocoap-client").setLevel(logging.INFO)
    elif verbosity == 2:
        logging.getLogger("coap").setLevel(logging.INFO)
    elif verbosity >= 3:
        logging.getLogger("coap").setLevel(logging.DEBUG)
    elif verbosity >= 4:
        logging.getLogger("coap").setLevel(0)

    log.debug("Logging configured.")


def colored(text, options, tokenlambda):
    """Apply pygments based coloring if options.color is set. Tokelambda is a
    callback to which pygments.token is passed and which returns a token type;
    this makes it easy to not need to conditionally react to pygments' possible
    absence in all color locations."""
    if not options.color:
        return str(text)

    from pygments.formatters import TerminalFormatter
    from pygments import token, format

    return format(
        [(tokenlambda(token), str(text))],
        TerminalFormatter(),
    )


def incoming_observation(options, response):
    log.info("Received Observe notification:")
    for line in message_to_text(response, "from"):
        log.info(line)

    if options.observe_exec:
        p = subprocess.Popen(options.observe_exec, shell=True, stdin=subprocess.PIPE)
        # FIXME this blocks
        p.communicate(response.payload)
    else:
        sys.stdout.write(colored("---", options, lambda token: token.Comment.Preproc))
        sys.stdout.write("\n")
        if response.code.is_successful():
            present(response, options, file=sys.stderr)
        else:
            print(
                colored(
                    response.code, options, lambda token: token.Token.Generic.Error
                ),
                file=sys.stderr,
            )
            if response.payload:
                present(response, options, file=sys.stderr)
        sys.stdout.flush()


def apply_credentials(context, credentials, errfn):
    try:
        if credentials.suffix == ".json":
            import json

            context.client_credentials.load_from_dict(json.load(credentials.open("rb")))
        elif credentials.suffix == ".diag":
            try:
                import cbor_diag
                import cbor2
            except ImportError:
                raise errfn(
                    "Loading credentials in CBOR diagnostic format requires cbor2 and cbor_diag package"
                )
            context.client_credentials.load_from_dict(
                cbor2.loads(cbor_diag.diag2cbor(credentials.open().read()))
            )
        else:
            raise errfn(
                "Unknown suffix: %s (expected: .json or .diag)" % (credentials.suffix)
            )
    except FileNotFoundError as e:
        raise errfn("Credential file not found: %s" % e.filename)
    except (OSError, ValueError) as e:
        # Any of the parsers could reasonably raise those, and while they don't
        # have HelpfulError support, they should still not render a backtrace
        # but a proper CLI error.
        raise errfn("Processing credential file: %s" % e)


def message_to_text(m, direction):
    """Convert a message to a text form similar to how they are shown in RFCs.

    Refactoring this into a message method will need to address the direction
    discovery eventually."""
    if m.remote is None:
        # This happens when unprocessable remotes are, eg. putting in an HTTP URI
        yield f"{m.code} {direction} (unknown)"
    else:
        # FIXME: Update when transport-indication is available
        # FIXME: This is slightly wrong because it does not account for what ProxyRedirector does
        yield f"{m.code} {direction} {m.remote.scheme}://{m.remote.hostinfo}"
    for opt in m.opt.option_list():
        if hasattr(opt.number, "name"):
            yield f"- {opt.number.name_printable} ({opt.number.value}): {opt.value!r}"
        else:
            yield f"- {opt.number.value}: {opt.value!r}"
    if m.payload:
        limit = 16
        if len(m.payload) > limit:
            yield f"Payload: {m.payload[:limit].hex()}... ({len(m.payload)} bytes total)"
        else:
            yield f"Payload: {m.payload[:limit].hex()} ({len(m.payload)} bytes)"
    else:
        yield "No payload"


def present(message, options, file=sys.stdout):
    """Write a message payload to the output, pretty printing and/or coloring
    it as configured in the options."""
    if not options.quiet and (message.opt.location_path or message.opt.location_query):
        # FIXME: Percent encoding is completely missing; this would be done
        # most easily with a CRI library
        location_ref = "/" + "/".join(message.opt.location_path)
        if message.opt.location_query:
            location_ref += "?" + "&".join(message.opt.location_query)
        print(
            colored(
                f"Location options indicate new resource: {location_ref}",
                options,
                lambda token: token.Token.Generic.Inserted,
            ),
            file=sys.stderr,
        )

    if not message.payload:
        return

    payload = None

    cf = message.opt.content_format

    if cf is None:
        if message.code.is_successful():
            cf = message.request.opt.content_format
        else:
            cf = ContentFormat.TEXT

    if cf is not None and cf.is_known():
        mime = cf.media_type
    else:
        mime = "application/octet-stream"
    if options.pretty_print:
        from aiocoap.util.prettyprint import pretty_print

        prettyprinted = pretty_print(message)
        if prettyprinted is not None:
            (infos, mime, payload) = prettyprinted
            if not options.quiet:
                for i in infos:
                    print(
                        colored("# " + i, options, lambda token: token.Comment),
                        file=sys.stderr,
                    )

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
            payload = message.payload.decode("utf8")
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
            if file.isatty() and message.payload[-1:] != b"\n":
                file.write("\n")
        else:
            file.write(payload)
            if file.isatty() and payload[-1] != "\n":
                file.write("\n")


async def single_request(args, context, globalopts=None):
    parser = build_parser(use_global=globalopts is None)
    options = parser.parse_args(args, copy.copy(globalopts))

    pretty_print_modules = aiocoap.defaults.prettyprint_missing_modules()
    if pretty_print_modules and (options.color is True or options.pretty_print is True):
        parser.error(
            "Color and pretty printing require the following"
            " additional module(s) to be installed: %s"
            % ", ".join(pretty_print_modules)
        )
    if options.color is None:
        options.color = sys.stdout.isatty() and not pretty_print_modules
    if options.pretty_print is None:
        options.pretty_print = sys.stdout.isatty() and not pretty_print_modules

    try:
        try:
            code = getattr(
                aiocoap.numbers.codes.Code,
                options.method.upper().replace("IPATCH", "iPATCH"),
            )
        except AttributeError:
            try:
                code = aiocoap.numbers.codes.Code(int(options.method))
            except ValueError:
                raise parser.error("Unknown method")

        if options.credentials is not None:
            apply_credentials(context, options.credentials, parser.error)

        request = aiocoap.Message(
            code=code,
            transport_tuning=aiocoap.Unreliable if options.non else aiocoap.Reliable,
        )
        request.set_request_uri(options.url, set_uri_host=options.set_hostname)

        if options.accept:
            try:
                request.opt.accept = ContentFormat(int(options.accept))
            except ValueError:
                try:
                    request.opt.accept = ContentFormat.by_media_type(options.accept)
                except KeyError:
                    raise parser.error("Unknown accept type")

        if options.observe:
            request.opt.observe = 0

        if options.content_format:
            try:
                request.opt.content_format = ContentFormat(int(options.content_format))
            except ValueError:
                try:
                    request.opt.content_format = ContentFormat.by_media_type(
                        options.content_format
                    )
                except KeyError:
                    raise parser.error("Unknown content format")

        if options.payload:
            if options.payload.startswith("@"):
                filename = options.payload[1:]
                if filename == "-":
                    f = sys.stdin.buffer
                else:
                    f = open(filename, "rb")
                try:
                    request.payload = f.read()
                except OSError as e:
                    raise parser.error("File could not be opened: %s" % e)
            else:
                request_classification = contenttype.categorize(
                    request.opt.content_format.media_type
                    if request.opt.content_format is not None
                    and request.opt.content_format.is_known()
                    else ""
                )
                if request_classification in ("cbor", "cbor-seq"):
                    try:
                        import cbor_diag
                    except ImportError as e:
                        raise parser.error(f"CBOR recoding not available ({e})")

                    try:
                        encoded = cbor_diag.diag2cbor(options.payload)
                    except ValueError as e:
                        raise parser.error(
                            f"Parsing CBOR diagnostic notation failed. Make sure quotation marks are escaped from the shell. Error: {e}"
                        )

                    if request_classification == "cbor-seq":
                        try:
                            import cbor2
                        except ImportError as e:
                            raise parser.error(
                                f"CBOR sequence recoding not available ({e})"
                            )
                        decoded = cbor2.loads(encoded)
                        if not isinstance(decoded, list):
                            raise parser.error(
                                "CBOR sequence recoding requires an array as the top-level element."
                            )
                        request.payload = b"".join(cbor2.dumps(d) for d in decoded)
                    else:
                        request.payload = encoded
                else:
                    request.payload = options.payload.encode("utf8")

        if options.payload_initial_szx is not None:
            request.remote.maximum_block_size_exp = options.payload_initial_szx

        if options.proxy is None or options.proxy in ("none", "", "-"):
            interface = context
        else:
            interface = aiocoap.proxy.client.ProxyForwarder(options.proxy, context)

        requested_uri = request.get_request_uri()

        log.info("Sending request:")
        for line in message_to_text(request, "to"):
            log.info(line)

        requester = interface.request(request)

        response_data = await requester.response

        log.info("Received response:")
        for line in message_to_text(response_data, "from"):
            log.info(line)

        response_uri = response_data.get_request_uri()
        if requested_uri != response_uri:
            print(
                colored(
                    f"Response arrived from different address; base URI is {response_uri}",
                    options,
                    lambda token: token.Generic.Inserted,
                ),
                file=sys.stderr,
            )
        if response_data.code.is_successful():
            present(response_data, options)
        else:
            print(
                colored(response_data.code, options, lambda token: token.Generic.Error),
                file=sys.stderr,
            )
            present(response_data, options, file=sys.stderr)
            sys.exit(1)

        if options.observe:
            try:
                async for notification in requester.observation:
                    incoming_observation(options, notification)
            except Exception as exit_reason:
                print("Observation is over: %r" % (exit_reason,), file=sys.stderr)
    except aiocoap.error.HelpfulError as e:
        print(str(e), file=sys.stderr)
        extra_help = e.extra_help(
            hints=dict(
                original_uri=options.url,
                request=request,
            )
        )
        if extra_help:
            print("Debugging hint:", extra_help, file=sys.stderr)
        sys.exit(1)
    # Fallback while not all backends raise NetworkErrors
    except OSError as e:
        text = str(e)
        if not text:
            text = repr(e)
        if not text:
            # eg ConnectionResetError flying out of a misconfigured SSL server
            text = type(e)
        print(
            "Warning: OS errors should not be raised this way any more.",
            file=sys.stderr,
        )
        # not telling what to do precisely: the form already tells users to
        # include `aiocoap.cli.defaults` output, which is exactly what we
        # need.
        print(
            f"Even if the cause of the error itself is clear, please file an issue at {aiocoap.meta.bugreport_uri}.",
            file=sys.stderr,
        )
        print("Error:", text, file=sys.stderr)
        sys.exit(1)


async def single_request_with_context(args):
    """Wrapper around single_request until sync_main gets made fully async, and
    async context managers are used to manage contexts."""
    context = await aiocoap.Context.create_client_context()
    try:
        await single_request(args, context)
    finally:
        await context.shutdown()


interactive_expecting_keyboard_interrupt = None


async def interactive(globalopts):
    global interactive_expecting_keyboard_interrupt
    interactive_expecting_keyboard_interrupt = asyncio.get_event_loop().create_future()

    context = await aiocoap.Context.create_client_context()

    while True:
        try:
            # when http://bugs.python.org/issue22412 is resolved, use that instead
            line = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("aiocoap> ")
            )
        except EOFError:
            line = "exit"
        line = shlex.split(line)
        if not line:
            continue
        if line in (["help"], ["?"]):
            line = ["--help"]
        if line in (["quit"], ["q"], ["exit"]):
            break

        async def single_request_noexit(*args, **kwargs):
            """Protects a run against the exit automatically generated by
            argparse errors or help"""
            try:
                # We could also set exit_on_error, but this way we do get the
                # original error code and can show that; might still revisit.
                await single_request(*args, **kwargs)
            except SystemExit as e:
                return e.code
            else:
                return 0

        current_task = asyncio.create_task(
            single_request_noexit(line, context=context, globalopts=globalopts),
            name="Interactive prompt command %r" % line,
        )
        interactive_expecting_keyboard_interrupt = (
            asyncio.get_event_loop().create_future()
        )

        done, pending = await asyncio.wait(
            [current_task, interactive_expecting_keyboard_interrupt],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if current_task not in done:
            current_task.cancel()
        else:
            try:
                code = await current_task
            except Exception as e:
                print("Unhandled exception raised: %s" % (e,))
            if code != 0:
                print("Exit code: %d" % code, file=sys.stderr)

    await context.shutdown()


async def main(args=None):
    # interactive mode is a little messy, that's why this is not using aiocoap.util.cli yet
    if args is None:
        args = sys.argv[1:]

    # This one is tolerant and doesn't even terminate with --help, so that
    # --help and --interactive --help can do the right thing.
    first_parser = build_parser(prescreen=True)
    first_args = first_parser.parse_args(args)

    configure_logging(
        (first_args.verbose or 0) - (first_args.quiet or 0), first_args.color
    )

    if not first_args.interactive:
        try:
            await single_request_with_context(args)
        except asyncio.exceptions.CancelledError:
            sys.exit(3)
    else:
        global_parser = build_parser(use_interactive=False)
        globalopts = global_parser.parse_args(args)

        loop = asyncio.get_event_loop()

        def ctrl_c():
            try:
                interactive_expecting_keyboard_interrupt.set_result(None)
            except asyncio.exceptions.InvalidStateError:
                # Too many Ctlr-C before the program could clean up
                sys.exit(3)

        loop.add_signal_handler(signal.SIGINT, ctrl_c)

        await interactive(globalopts)


def sync_main(args=None):
    asyncio.run(main(args=args))


if __name__ == "__main__":
    sync_main()
