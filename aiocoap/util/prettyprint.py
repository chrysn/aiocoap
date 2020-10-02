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
import re

import cbor2 as cbor
import pygments, pygments.lexers, pygments.formatters

from aiocoap.numbers import media_types
from aiocoap.util import linkformat, contenttype

from aiocoap.util.linkformat_pygments import _register

_register()

MEDIATYPE_HEXDUMP = 'text/vnd.aiocoap.hexdump'

def lexer_for_mime(mime):
    """A wrapper around pygments.lexers.get_lexer_for_mimetype that takes
    subtypes into consideration and catches the custom hexdump mime type."""

    if mime == MEDIATYPE_HEXDUMP:
        return pygments.lexers.HexdumpLexer()

    if mime == 'text/plain;charset=utf8':
        # We have fall-throughs in place anwyay, no need to go through a no-op
        # TextLexer
        raise pygments.util.ClassNotFound

    try:
        return pygments.lexers.get_lexer_for_mimetype(mime)
    except pygments.util.ClassNotFound:
        mime = re.sub('^([^/]+)/.*\\+([^;]+)(;.*)?$',
                lambda args: args[1] + '/' + args[2], mime)
        return pygments.lexers.get_lexer_for_mimetype(mime)

def pretty_print(message):
    """Given a CoAP message, reshape its payload into something human-readable.
    The return value is a triple (infos, mime, text) where text represents the
    payload, mime is a type that could be used to syntax-highlight the text
    (not necessarily related to the original mime type, eg. a report of some
    binary data that's shaped like Markdown could use a markdown mime type),
    and some line of infos that give additional data (like the reason for a hex
    dump or the original mime type).
    """
    infos = []
    info = lambda m: infos.append(m)

    cf = message.opt.content_format
    if cf is None:
        cf = message.request.opt.accept
    content_type = media_types.get(cf, "type %s" % cf)
    category = contenttype.categorize(content_type)

    show_hex = None

    if linkformat is not None and category == 'link-format':
        try:
            parsed = linkformat.link_header.parse(message.payload.decode('utf8'))
        except ValueError:
            pass
        else:
            info("application/link-format content was re-formatted")
            prettyprinted = ",\n".join(str(l) for l in parsed.links)
            return (infos, 'application/link-format', prettyprinted)

    elif category == 'cbor':
        try:
            parsed = cbor.loads(message.payload)
        except ValueError:
            show_hex = "CBOR value is invalid"
        else:
            info("CBOR message shown in naïve Python decoding")
            # Formatting it via Python b/c that's reliably available (as
            # opposed to JSON which might not round-trip well). The repr for
            # tags might still not be parsable, but I think chances of good
            # highlighting are best this way
            #
            # Not sorting dicts to give a more faithful representation of the
            # original CBOR message
            if sys.version_info >= (3, 8):
                printer = pprint.PrettyPrinter(sort_dicts=False)
            else:
                printer = pprint.PrettyPrinter()
            formatted = printer.pformat(parsed)
            return (infos, 'text/x-python3', formatted)

    elif category == 'json':
        try:
            parsed = json.loads(message.payload.decode('utf8'))
        except ValueError:
            pass
        else:
            info("JSON re-formated and indented")
            formatted = json.dumps(parsed, indent=4)
            return (infos, 'application/json', formatted)

    # That's about the formats we do for now.

    if show_hex is None:
        try:
            text = message.payload.decode('utf8')
        except UnicodeDecodeError:
            show_hex = "Message can not be parsed as UTF-8"
        else:
            return (infos, 'text/plain;charset=utf8', text)

    info("Showing hex dump of %s payload%s" % (
        content_type if cf is not None else "untyped",
        ": " + show_hex if show_hex is not None else ""))
    data = message.payload
    # Not the most efficient hex dumper, but we won't stream video over
    # this anyway
    formatted = []
    offset = 0
    while data:
        line, data = data[:16], data[16:]

        formatted.append("%08x  " % offset + \
                " ".join("%02x" % line[i] if i < len(line) else "  " for i in range(8)) + "  " + \
                " ".join("%02x" % line[i] if i < len(line) else "  " for i in range(8, 16)) + "  |" + \
                "".join(chr(x) if 32 <= x < 127 else '.' for x in line) + \
                "|\n")

        offset += len(line)
    if offset % 16 != 0:
        formatted.append("%08x\n" % offset)
    return (infos, MEDIATYPE_HEXDUMP, "".join(formatted))
