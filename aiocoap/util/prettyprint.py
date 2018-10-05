# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""A pretty-printer for known mime types"""

import json
import sys
import pprint

import termcolor
import cbor
import pygments, pygments.lexers, pygments.formatters

from aiocoap.numbers import media_types
from aiocoap.util import linkformat

def _info(message):
    """Write a colorful message to stderr"""

    print(termcolor.colored(message, 'white', attrs=['dark']), file=sys.stderr)

def pretty_print(message, quiet=False):
    if quiet:
        info = lambda: ()
    else:
        info = _info

    cf = message.opt.content_format
    mime_type = media_types.get(cf, "type %s" % cf)

    mime_type, *parameters = mime_type.split(';')
    type, _, subtype = mime_type.partition('/')

    show_hex = None

    if linkformat is not None and mime_type == 'application/link-format':
        try:
            parsed = linkformat.link_header.parse(message.payload.decode('utf8'))
        except ValueError:
            pass
        else:
            prettyprinted = ",\n".join(str(l) for l in parsed.links)
            print(pygments.highlight(
                    prettyprinted,
                    LinkFormatLexer(),
                    pygments.formatters.TerminalFormatter()
                    ))
            return

    elif subtype == 'cbor' or subtype.endswith('+cbor'):
        try:
            parsed = cbor.loads(message.payload)
        except ValueError:
            show_hex = "No CBOR library available"
        else:
            # Formatting it via Python b/c that's reliably available (as
            # opposed to JSON which might not round-trip well). The repr for
            # tags might still not be parsable, but I think chances of good
            # highlighting are best this way
            formatted = pprint.pformat(parsed)
            print(pygments.highlight(
                    formatted,
                    pygments.lexers.PythonLexer(),
                    pygments.formatters.TerminalFormatter()
                    ))
            return

    elif subtype == 'json' or subtype.endswith('+json'):
        try:
            parsed = json.loads(message.payload.decode('utf8'))
        except ValueError:
            pass
        else:
            info("JSON re-formated and highlighted")
            formatted = json.dumps(parsed, indent=4)

            print(pygments.highlight(
                    formatted,
                    pygments.lexers.JsonLexer(),
                    pygments.formatters.TerminalFormatter()
                    ))
            return

    # That's about the formats we do for now.

    try:
        text = message.payload.decode('utf8')
    except UnicodeDecodeError:
        show_hex = "Message can not be parsed as UTF-8"
    else:
        sys.stdout.write(text)
        sys.stdout.flush()
        if text and not text.endswith("\n") and not quiet:
            info("\n(No newline at end of message)")

    if show_hex is not None:
        info("Showing hex dump of %s payload: %s" % (
            mime_type if cf is not None else "untyped",
            show_hex))
        data = message.payload
        while data:
            # Not the most efficient hex dumper, but we won't stream video over
            # this anyway
            line, data = data[:16], data[16:]
            print(line.hex())


from pygments import token, lexer
from pygments.lexer import RegexLexer, bygroups
class LinkFormatLexer(RegexLexer):
    name = "LinkFormat"

    tokens = {
        'root': [
            ('(<)([^>]*)(>)', bygroups(token.Punctuation, token.Name.Label, token.Punctuation), 'maybe-end')
            ],
        'maybe-end': [
            # Whitespace is not actually allowed, but produced by the pretty printer
            (';\\s*', token.Punctuation, 'attribute'),
            (',\\s*', token.Punctuation, 'root'),
            ],
        'attribute': [
            ('([^,;=]+)((=)("[^,;"]+"|[^,;"]+))?', bygroups(token.Name.Attribute, None, token.Operator, token.String.Symbol), 'maybe-end'),
            ],
        }
