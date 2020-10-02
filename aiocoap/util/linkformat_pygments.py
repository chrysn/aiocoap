# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from pygments import token, lexer, lexers
from pygments.lexer import RegexLexer, bygroups

__all__ = ['LinkFormatLexer']

class LinkFormatLexer(RegexLexer):
    name = "LinkFormatLexer"
    mimetypes = ['application/link-format']

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
            ('([^,;=]+)((=)("[^"]*"|[^,;"]+))?', bygroups(token.Name.Attribute, None, token.Operator, token.String.Symbol), 'maybe-end'),
            ],
        }

def _register():
    if 'LinkFormatLexer' not in lexers.LEXERS:
        lexers.LEXERS['LinkFormatLexer'] = (
                'aiocoap.util.linkformat_pygments',
                'LinkFormatLexer',
                (),
                (),
                LinkFormatLexer.mimetypes,
                )
