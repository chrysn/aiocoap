# SPDX-FileCopyrightText: Michael Burrows <mjb@asplake.co.uk>
#
# SPDX-License-Identifier: BSD-3-Clause

'''
Parse and format link headers according to RFC 5988 "Web Linking".

Usage (assuming a suitable headers object in the environment):

>>> headers['Link'] = str(LinkHeader([Link("http://example.com/foo", rel="self"),
...                                   Link("http://example.com", rel="up")]))
>>> headers['Link']
'<http://example.com/foo>; rel=self, <http://example.com>; rel=up'
>>> parse(headers['Link'])
LinkHeader([Link('http://example.com/foo', rel='self'), Link('http://example.com', rel='up')])

Blank and missing values roundtrip correctly:

>>> format_link(parse('</s/1>; obs; if="core.s"; foo=""'))
'<</s/1>; obs; if=core.s; foo="">'

Conversions to and from json-friendly list-based structures are also provided:

>>> parse(headers['Link']).to_py()
[['http://example.com/foo', [['rel', 'self']]], ['http://example.com', [['rel', 'up']]]]
>>> str(LinkHeader([['http://example.com/foo', [['rel', 'self']]],
...                 ['http://example.com', [['rel', 'up']]]]))
'<http://example.com/foo>; rel=self, <http://example.com>; rel=up'

For further information see parse(), LinkHeader and Link.
'''

import re
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

__all__ = ['parse', 'format_links', 'format_link', 'LinkHeader', 'Link', 'ParseException']

SINGLE_VALUED_ATTRS = ['rel', 'anchor', 'rev', 'media', 'title', 'title*', 'type']

#
# Regexes for link header parsing.  TOKEN and QUOTED in particular should conform to RFC2616.
#
# Acknowledgement: The QUOTED regexp is based on
# http://stackoverflow.com/questions/249791/regexp-for-quoted-string-with-escaping-quotes/249937#249937
#
# Trailing spaces are consumed by each pattern.  The RE_HREF pattern also allows for any leading spaces.
#

QUOTED        = r'"((?:[^"\\]|\\.)*)"'                  # double-quoted strings with backslash-escaped double quotes
TOKEN         = r'([^()<>@,;:\"\[\]?={}\s]+)'           # non-empty sequence of non-separator characters
RE_COMMA_HREF = re.compile(r' *,? *< *([^>]*) *> *')    # includes ',' separator; no attempt to check URI validity
RE_ONLY_TOKEN = re.compile(r'^%(TOKEN)s$' % locals())
RE_ATTR       = re.compile(r'%(TOKEN)s *(?:= *(%(TOKEN)s|%(QUOTED)s))? *' % locals())
RE_SEMI       = re.compile(r'; *')
RE_COMMA      = re.compile(r', *')


def parse(header):
    '''Parse a link header string, returning a LinkHeader object:

    >>> parse('<http://example.com/foo>; rel="foo bar", <http://example.com>; rel=up; type=text/html')
    LinkHeader([Link('http://example.com/foo', rel='foo bar'), Link('http://example.com', rel='up', type='text/html')])

    ParseException is raised in the event that the input string is not parsed completely:

    >>> parse('<http://example.com/foo> error') #doctest: +SKIP
    Traceback (most recent call last):
        ...
    ParseException: ('link_header.parse() failed near %s', "'error'")
    '''
    scanner = _Scanner(header)
    links = []
    while scanner.scan(RE_COMMA_HREF):
        href = scanner[1]
        attrs = []
        while scanner.scan(RE_SEMI):
            if scanner.scan(RE_ATTR):
                attr_name, token, quoted = scanner[1], scanner[3], scanner[4]
                if quoted is not None:
                    attrs.append([attr_name, quoted.replace(r'\"', '"')])
                elif token is not None:
                    attrs.append([attr_name, token])
                else:
                    attrs.append([attr_name, None])
        links.append(Link(href, attrs))

    if scanner.buf:
        raise ParseException("link_header.parse() failed near %s", repr(scanner.buf))

    return LinkHeader(links)

def format_links(*args, **kwargs):
    return str(LinkHeader(*args, **kwargs))

def format_link(*args, **kwargs):
    return str(Link(*args, **kwargs))


class ParseException(Exception):
    pass


class LinkHeader(object):
    '''Represents a sequence of links that can be formatted together as a link header.
    '''
    def __init__(self, links=None):
        '''Initializes a LinkHeader object with a list of Link objects or with
        list of parameters from which Link objects can be created:

        >>> LinkHeader([Link('http://example.com/foo', rel='foo'), Link('http://example.com', rel='up')])
        LinkHeader([Link('http://example.com/foo', rel='foo'), Link('http://example.com', rel='up')])
        >>> LinkHeader([['http://example.com/foo', [['rel', 'foo']]], ['http://example.com', [['rel', 'up']]]])
        LinkHeader([Link('http://example.com/foo', rel='foo'), Link('http://example.com', rel='up')])

        The Link objects can be accessed afterwards via the `links` property.

        String conversion follows the spec:

        >>> str(LinkHeader([Link('http://example.com/foo', rel='foo'), Link('http://example.com', rel='up')]))
        '<http://example.com/foo>; rel=foo, <http://example.com>; rel=up'

        Conversion to json-friendly list-based structures:

        >>> LinkHeader([Link('http://example.com/foo', rel='foo'), Link('http://example.com', rel='up')]).to_py()
        [['http://example.com/foo', [['rel', 'foo']]], ['http://example.com', [['rel', 'up']]]]

        '''

        self.links = [
            link if isinstance(link, Link) else Link(*link)
            for link in links or []]

    def to_py(self):
        '''Supports list conversion:

        >>> LinkHeader([Link('http://example.com/foo', rel='foo'), Link('http://example.com', rel='up')]).to_py()
        [['http://example.com/foo', [['rel', 'foo']]], ['http://example.com', [['rel', 'up']]]]
        '''
        return [link.to_py() for link in self.links]

    def __repr__(self):
        return 'LinkHeader([%s])' % ', '.join(repr(link) for link in self.links)

    def __str__(self):
        '''Formats a link header:

        >>> str(LinkHeader([Link('http://example.com/foo', rel='foo'), Link('http://example.com', rel='up')]))
        '<http://example.com/foo>; rel=foo, <http://example.com>; rel=up'
        '''
        return ', '.join(str(link) for link in self.links)

    def links_by_attr_pairs(self, pairs):
        '''Lists links that have attribute pairs matching all the supplied pairs:

         >>> parse('<http://example.com/foo>; rel="foo", <http://example.com>; rel="up"'
         ...      ).links_by_attr_pairs([('rel', 'up')])
         [Link('http://example.com', rel='up')]
        '''
        return [link
                for link in self.links
                if all([key, value] in link.attr_pairs
                       for key, value in pairs)]

class Link(object):
    '''Represents a single link.
    '''

    def __init__(self, href, attr_pairs=None, **kwargs):
        '''Initializes a Link object with an href and attributes either in
        the form of a sequence of key/value pairs &/or as keyword arguments.
        The sequence form allows to be repeated.  Attributes may be accessed
        subsequently via the `attr_pairs` property.

        String conversion follows the spec:

        >>> str(Link('http://example.com', [('foo', 'bar'), ('foo', 'baz')], rel='self'))
        '<http://example.com>; foo=bar; foo=baz; rel=self'

        Conversion to json-friendly list-based structures:

        >>> Link('http://example.com', [('foo', 'bar'), ('foo', 'baz')], rel='self').to_py()
        ['http://example.com', [['foo', 'bar'], ['foo', 'baz'], ['rel', 'self']]]
        '''
        self.href = href
        self.attr_pairs = [
            list(pair)
            for pair in (attr_pairs or []) + list(kwargs.items())]

    def to_py(self):
        '''Convert to a json-friendly list-based structure:

        >>> Link('http://example.com', rel='foo').to_py()
        ['http://example.com', [['rel', 'foo']]]
        '''
        return [self.href, self.attr_pairs]

    def __repr__(self):
        '''
        >>> Link('http://example.com', rel='self')
        Link('http://example.com', rel='self')
        '''
        return 'Link(%s)' % ', '.join(
            [
                repr(self.href)
            ] + [
                "%s=%s" % (pair[0], repr(pair[1]))
                for pair in self.attr_pairs])

    def __str__(self):
        '''Formats a single link:

        >>> str(Link('http://example.com/foo', [['rel', 'self']]))
        '<http://example.com/foo>; rel=self'
        >>> str(Link('http://example.com/foo', [['rel', '"quoted"'], ['type', 'text/html'], ['title*', "UTF-8'en'%e2%82%ac%20rates"]]))
        '<http://example.com/foo>; rel="\\\\"quoted\\\\""; type=text/html; title*=UTF-8\\'en\\'%e2%82%ac%20rates'

        Note that there is no explicit support for the title* attribute other
        than to output it unquoted.  Where used, it is up to client applications to
        provide values that meet RFC2231 Section 7.
        '''
        def str_pair(key, value):
            if value is None:
                return key
            elif RE_ONLY_TOKEN.match(value) or key.endswith('*'):
                return '%s=%s' % (key, value)
            else:
                return '%s="%s"' % (key, value.replace('"', r'\"'))
        return '; '.join(['<%s>' % self.href] +
                         [str_pair(key, value)
                          for key, value in self.attr_pairs])

    def __getattr__(self, name):
        '''
        >>> Link('/', rel='self').rel
        'self'
        >>> Link('/', hreflang='EN').hreflang
        ['EN']
        >>> Link('/', foo='bar').foo
        ['bar']
        >>> Link('/', [('foo', 'bar'), ('foo', 'baz')]).foo
        ['bar', 'baz']
        >>> Link('/').rel #doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        AttributeError: No attribute of type 'rel' present
        >>> Link('/').hreflang
        []
        >>> Link('/').foo
        []
        '''
        name_lower = name.lower()
        values = [value
                  for key, value in self.attr_pairs
                  if key.lower() == name_lower]
        if name in SINGLE_VALUED_ATTRS:
            if values:
                return values[0]
            else:
                raise AttributeError("No attribute of type %r present"%name_lower)
        return values

    def __contains__(self, name):
        '''
        >>> 'rel' in Link('/', rel='self')
        True
        >>> 'obs' in Link('/', obs=None)
        True
        >>> 'rel' in Link('/')
        False
        '''
        name_lower = name.lower()
        return any(key.lower() == name_lower for key, value in self.attr_pairs)

    def get_context(self, requested_resource_address):
        '''Return the absolute URI of the context of a link. This is usually
        equals the base address the statement is about (eg. the requested URL
        if the link header was served in a successful HTTP GET request), but
        can be overridden by the anchor parameter.

        >>> Link('../', rel='index').get_context('http://www.example.com/book1/chapter1/')
        'http://www.example.com/book1/chapter1/'
        >>> Link('', rel='next', anchor='../').get_context('http://www.example.com/book1/chapter1/')
        'http://www.example.com/book1/'
        '''
        if 'anchor' in self:
            return urljoin(requested_resource_address, self.anchor)
        return requested_resource_address

    def get_target(self, requested_resource_address):
        '''Return the absolute URI of the target of a link. It is determined by
        joining the address from which the link header was retrieved with the
        link-value (inside angular brackets) according to RFC3986 section 5.

        >>> Link('../', rel='index').get_target('http://www.example.com/book1/chapter1/')
        'http://www.example.com/book1/'
        >>> Link('', rel='next', anchor='../').get_target('http://www.example.com/book1/chapter1/')
        'http://www.example.com/book1/chapter1/'
        '''
        return urljoin(requested_resource_address, self.href)

class _Scanner(object):
    def __init__(self, buf):
        self.buf = buf
        self.match = None

    def __getitem__(self, key):
        return self.match.group(key)

    def scan(self, pattern):
        self.match = pattern.match(self.buf)
        if self.match:
            self.buf = self.buf[self.match.end():]
        return self.match


# For doctest
headers = dict()
