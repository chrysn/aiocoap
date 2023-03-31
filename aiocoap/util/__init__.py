# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tools not directly related with CoAP that are needed to provide the API

These are only part of the stable API to the extent they are used by other APIs
-- for example, you can use the type constructor of :class:`ExtensibleEnumMeta`
when creating an :class:`aiocoap.numbers.optionnumbers.OptionNumber`, but don't
expect it to be usable in a stable way for own extensions.

Most functions are available in submodules; some of them may only have
components that are exclusively used internally and never part of the public
API even in the limited fashion stated above.

.. toctree::
    :glob:

    aiocoap.util.*
"""

import urllib.parse

class ExtensibleEnumMeta(type):
    """Metaclass for ExtensibleIntEnum, see there for detailed explanations"""
    def __init__(self, name, bases, dict):
        self._value2member_map_ = {}
        for k, v in dict.items():
            if k.startswith('_'):
                continue
            if callable(v):
                continue
            if isinstance(v, property):
                continue
            if isinstance(v, classmethod):
                continue
            instance = self(v)
            instance.name = k
            setattr(self, k, instance)
        type.__init__(self, name, bases, dict)

    def __call__(self, value):
        if isinstance(value, self):
            return value
        if value not in self._value2member_map_:
            self._value2member_map_[value] = super(ExtensibleEnumMeta, self).__call__(value)
        return self._value2member_map_[value]

class ExtensibleIntEnum(int, metaclass=ExtensibleEnumMeta):
    """Similar to Python's enum.IntEnum, this type can be used for named
    numbers which are not comprehensively known, like CoAP option numbers."""

    def __repr__(self):
        return '<%s %d%s>' % (type(self).__name__, self, ' "%s"' % self.name if hasattr(self, "name") else "")

    def __str__(self):
        return self.name if hasattr(self, "name") else int.__str__(self)

    def _repr_html_(self):
        import html
        if hasattr(self, "name"):
            return f'<abbr title="{html.escape(type(self).__name__)} {int(self)}">{html.escape(self.name)}</abbr>'
        else:
            return f'<abbr title="Unknown {html.escape(type(self).__name__)}">{int(self)}</abbr>'

def hostportjoin(host, port=None):
    """Join a host and optionally port into a hostinfo-style host:port
    string

    >>> hostportjoin('example.com')
    'example.com'
    >>> hostportjoin('example.com', 1234)
    'example.com:1234'
    >>> hostportjoin('127.0.0.1', 1234)
    '127.0.0.1:1234'

    This is lax with respect to whether host is an IPv6 literal in brackets or
    not, and accepts either form; IP-future literals that do not contain a
    colon must be already presented in their bracketed form:

    >>> hostportjoin('2001:db8::1')
    '[2001:db8::1]'
    >>> hostportjoin('2001:db8::1', 1234)
    '[2001:db8::1]:1234'
    >>> hostportjoin('[2001:db8::1]', 1234)
    '[2001:db8::1]:1234'
    """
    if ':' in host and not (host.startswith('[') and host.endswith(']')):
        host = '[%s]' % host

    if port is None:
        hostinfo = host
    else:
        hostinfo = "%s:%d" % (host, port)
    return hostinfo

def hostportsplit(hostport):
    """Like urllib.parse.splitport, but return port as int, and as None if not
    given. Also, it allows giving IPv6 addresses like a netloc:

    >>> hostportsplit('foo')
    ('foo', None)
    >>> hostportsplit('foo:5683')
    ('foo', 5683)
    >>> hostportsplit('[::1%eth0]:56830')
    ('::1%eth0', 56830)
    """

    pseudoparsed = urllib.parse.SplitResult(None, hostport, None, None, None)
    try:
        return pseudoparsed.hostname, pseudoparsed.port
    except ValueError:
        if '[' not in hostport and hostport.count(':') > 1:
            raise ValueError("Could not parse network location. "
                "Beware that when IPv6 literals are expressed in URIs, they "
                "need to be put in square brackets to distinguish them from "
                "port numbers.")
        raise

def quote_nonascii(s):
    """Like urllib.parse.quote, but explicitly only escaping non-ascii characters.

    This function is deprecated due to it use of the irrelevant "being an ASCII
    character" property (when instead RFC3986 productions like "unreserved"
    should be used), and due for removal when aiocoap's URI processing is
    overhauled the next time.
    """

    return "".join(chr(c) if c <= 127 else "%%%02X" % c for c in s.encode('utf8'))

class Sentinel:
    """Class for sentinel that can only be compared for identity. No efforts
    are taken to make these singletons; it is up to the users to always refer
    to the same instance, which is typically defined on module level."""
    def __init__(self, label):
        self._label = label

    def __repr__(self):
        return '<%s>' % self._label

def deprecation_getattr(_deprecated_aliases: dict, _globals: dict):
    """Factory for a module-level ``__getattr__`` function

    This creates deprecation warnings whenever a module level item by one of
    the keys of the alias dict is accessed by its old name rather than by its
    new name (which is in the values):

    >>> FOOBAR = 42
    >>>
    >>> __getattr__ = deprecation_getattr({'FOOBRA': 'FOOBAR'}, globals())
    """
    def __getattr__(name):
        if name in _deprecated_aliases:
            modern = _deprecated_aliases[name]
            from warnings import warn
            warn(f"{name} is deprecated, use {modern} instead", DeprecationWarning,
                    stacklevel=2)
            return _globals[modern]
        raise AttributeError(f"module {__name__} has no attribute {name}")
    return __getattr__
