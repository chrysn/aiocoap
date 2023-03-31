# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""A pretty-printer for known mime types"""

import json
import re

import pygments
import pygments.lexers
import pygments.formatters

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

    >>> from aiocoap import Message
    >>> def build(payload, request_cf, response_cf):
    ...     response = Message(payload=payload, content_format=response_cf)
    ...     request = Message(accept=request_cf)
    ...     response.request = request
    ...     return response
    >>> pretty_print(Message(payload=b"Hello", content_format=0))
    ([], 'text/plain;charset=utf8', 'Hello')
    >>> print(pretty_print(Message(payload=b'{"hello":"world"}', content_format=50))[-1])
    {
        "hello": "world"
    }
    >>> # Erroneous inputs still go to the pretty printer as long as they're
    >>> #Unicode
    >>> pretty_print(Message(payload=b'{"hello":"world', content_format=50))
    (['Invalid JSON not re-formated'], 'application/json', '{"hello":"world')
    >>> pretty_print(Message(payload=b'<>,', content_format=40))
    (['Invalid application/link-format content was not re-formatted'], 'application/link-format', '<>,')
    >>> pretty_print(Message(payload=b'a', content_format=60)) # doctest: +ELLIPSIS
    (['Showing hex dump of application/cbor payload: CBOR value is invalid'], 'text/vnd.aiocoap.hexdump', '00000000  61 ...
    """
    infos = []
    info = infos.append

    cf = message.opt.content_format or message.request.opt.accept
    if cf is None:
        content_type = "type unknown"
    elif cf.is_known():
        content_type = cf.media_type
        if cf.encoding != 'identity':
            info("Content format is %s in %s encoding; treating as "
                 "application/octet-stream because decompression is not "
                 "supported yet" % (cf.media_type, cf.encoding))
    else:
        content_type = "type %d" % cf
    category = contenttype.categorize(content_type)

    show_hex = None

    if linkformat is not None and category == 'link-format':
        try:
            decoded = message.payload.decode('utf8')
            try:
                parsed = linkformat.link_header.parse(decoded)
            except linkformat.link_header.ParseException:
                info("Invalid application/link-format content was not re-formatted")
                return (infos, 'application/link-format', decoded)
            else:
                info("application/link-format content was re-formatted")
                prettyprinted = ",\n".join(str(l) for l in parsed.links)
                return (infos, 'application/link-format', prettyprinted)
        except ValueError:
            # Handled later
            pass

    elif category in ('cbor', 'cbor-seq'):
        if category == 'cbor-seq':
            # Faking an indefinite length CBOR array is the easiest way to
            # parse an array into a list-like data structure, especially as
            # long as we don't indicate precise locations of invalid CBOR
            # anyway
            payload = b'\x9f' + message.payload + b'\xff'
        else:
            payload = message.payload

        try:
            import cbor_diag

            formatted = cbor_diag.cbor2diag(payload)

            if category == 'cbor-seq':
                info("CBOR sequence message shown as array in Diagnostic Notation")
            else:
                info("CBOR message shown in Diagnostic Notation")

            # It's not exactly CDDL, but it's close enough that the syntax
            # highlighting looks OK, and tolerant enough to not complain about
            # missing leading barewords and "=" signs
            return (infos, 'text/x-cddl', formatted)
        except ImportError:
            show_hex = "No CBOR pretty-printer available"
        except ValueError:
            show_hex = "CBOR value is invalid"

    elif category == 'json':
        try:
            decoded = message.payload.decode('utf8')
        except ValueError:
            pass
        else:
            try:
                parsed = json.loads(decoded)
            except ValueError:
                info("Invalid JSON not re-formated")
                return (infos, 'application/json', decoded)
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

        formatted.append("%08x  " % offset +
                " ".join("%02x" % line[i] if i < len(line) else "  " for i in range(8)) + "  " +
                " ".join("%02x" % line[i] if i < len(line) else "  " for i in range(8, 16)) + "  |" +
                "".join(chr(x) if 32 <= x < 127 else '.' for x in line) +
                "|\n")

        offset += len(line)
    if offset % 16 != 0:
        formatted.append("%08x\n" % offset)
    return (infos, MEDIATYPE_HEXDUMP, "".join(formatted))
