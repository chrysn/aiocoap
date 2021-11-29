# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module describes how security credentials are expressed in aiocoap,
how security protocols (TLS, DTLS, OSCOAP) can store and access their key
material, and for which URIs they are used.

For consistency, mappings between accessible resources and their credentials
are always centered around URIs. This is slightly atypical, because a client
will typically use a particular set of credentials for all operations on one
server, while a server first loads all available credentials and then filters
out whether the client may actually access a resource per-path, but it works
with full URIs (or patterns thereof) just as well. That approach allows using
more similar structures both on the server and the client, and works smoothly
for virtual hosting, firewalling and clients accessing resources with varying
credentials.

Still, client and server credentials are kept apart, lest a server open up (and
potentially reveal) to a PSK set it is only configured to use as a client.
While client credentials already have their place in
:attr:`aiocoap.protocol.Context.client_credentials`, server credentials are not
in use at a standardized location yet because there is only code in the OSCORE
plug tests that can use it so far.

Library developer notes
~~~~~~~~~~~~~~~~~~~~~~~

This whole module currently relies on a mixture of introspection and manual
parsing of the JSON-ish tree. A preferred expression of the same would rely on
the credentials.cddl description and build an object tree from that, but the
author is unaware of any existing CDDL Python implementation. That might also
ease porting to platforms that don't support inspect like micropython does.
"""

import re
import inspect

from typing import Optional


'''
server: {
            'coaps://mysite/*': { 'dtls-psk' (or other granularity): { 'psk': 'abcd' }},
            'coap://mysite/*': { 'oscore': { 'contextfile': 'my-contextfile/' } },
            'coap://myothersite/firmware': ':myotherkey',
            'coap://myothersite/reset': ':myotherkey',
            'coap://othersite*': { 'unprotected': true },
            ':myotherkey': { 'oscore': { 'contextfile': 'my-contextfile/' } }
        }

server can of course just say it doesn't want to have the Site handle it and
just say '*': { 'unprotected': true }, add some ':foo': {'dtls-psk': ...}
entries (so communication can be established in the first place) and let
individual resources decide whether they return 4.01 or something else.

client can be the same with different implied role, or have something like

client: {
            'coap://myothersite/*': ':myotherkey',
            ...
        }

in future also

server: {
        'coaps://mysite/*': { 'dtls-cert': {'key': '...pem', 'cert': '...crt'} }
        }

client: {
        '*': { 'dtls-cert': { 'ca': '/etc/ssl/...' } }
}

or more complex ones:

server: {
        'coaps://myothersite/wellprotected': { 'all': [ ':mydtls', ':myotherkey' ]}
        'coaps://myothersite/*': { 'any': [ ':mydtls', ':myotherkey' ]}
}
'''

class CredentialsLoadError(ValueError):
    """Raised by functions that create a CredentialsMap or its parts from
    simple data structures"""

class CredentialsMissingError(RuntimeError):
    """Raised when no suiting credentials can be found for a message, or
    credentials are found but inapplicable to a transport's security
    mechanisms."""

class CredentialReference:
    def __init__(self, target, map):
        if not target.startswith(':'):
            raise CredentialsLoadError("Credential references must start with a colon (':')")
        self.target = target
        self.map = map

    # FIXME either generalize this with getattr, or introduce a function to
    # resolve any indirect credentials to a particular instance.

    def as_dtls_psk(self):
        return self.map[self.target].as_dtls_psk()

class _Listish(list):
    @classmethod
    def from_item(cls, v):
        if not isinstance(v, list):
            raise CredentialsLoadError("%s goes with a list" % cls.__name__)
        return cls(v)

class AnyOf(_Listish):
    pass

class AllOf(_Listish):
    pass

def _call_from_structureddata(constructor, name, init_data):
    if not isinstance(init_data, dict):
        raise CredentialsLoadError("%s goes with an object" % name)

    init_data = {k.replace('-', '_'): v for (k, v) in init_data.items()}

    sig = inspect.signature(constructor)

    checked_items = {}

    for k, v in init_data.items():
        try:
            annotation = sig.parameters[k].annotation
        except KeyError:
            # let this raise later in binding
            checked_items[k] = object()

        if isinstance(v, dict) and 'ascii' in v:
            if len(v) != 1:
                raise CredentialsLoadError("ASCII objects can only have one elemnt.")
            try:
                v = v['ascii'].encode('ascii')
            except UnicodeEncodeError:
                raise CredentialsLoadError("Elements of the ASCII object can not be represented in ASCII, please use binary or hex representation.")


        if isinstance(v, dict) and 'hex' in v:
            if len(v) != 1:
                raise CredentialsLoadError("Hex objects can only have one elemnt.")
            try:
                v = bytes.fromhex(v['hex'].replace('-', '').replace(' ', '').replace(':', ''))
            except ValueError as e:
                raise CredentialsLoadError("Hex object can not be read: %s" % (e.args[0]))

        # Not using isinstance because I foundno way to extract the type
        # information from an Optional/Union again; this whole thing works
        # only for strings and ints anyway, so why not.
        if type(v) != annotation and Optional[type(v)] != annotation:
            # explicitly not excluding inspect._empty here: constructors
            # need to be fully annotated
            raise CredentialsLoadError("Type mismatch in attribute %s of %s: expected %s, got %r" % (k, name, annotation, v))

        checked_items[k] = v

    try:
        bound = sig.bind(**checked_items)
    except TypeError as e:
        raise CredentialsLoadError("%s: %s" % (name, e.args[0]))

    return constructor(*bound.args, **bound.kwargs)

class _Objectish:
    @classmethod
    def from_item(cls, init_data):
        return _call_from_structureddata(cls, cls.__name__, init_data)

class DTLS(_Objectish):
    def __init__(self, psk: bytes, client_identity: bytes):
        self.psk = psk
        self.client_identity = client_identity

    def as_dtls_psk(self):
        return (self.client_identity, self.psk)

class TLSCert(_Objectish):
    """Indicates that a client can use the given certificate file to authenticate the server.

    Can only be used with 'coaps+tcp://HOSTINFO/*' and 'coaps+tcp://*' forms.
    """
    def __init__(self, certfile: str):
        self.certfile = certfile

    def as_ssl_params(self):
        """Generate parameters suitable for passing via ** to
        ssl.create_default_context when purpose is alreay set"""
        return {"cafile": self.certfile}

def construct_oscore(contextfile: str):
    from .oscore import FilesystemSecurityContext

    return FilesystemSecurityContext(contextfile)

construct_oscore.from_item = lambda value: _call_from_structureddata(construct_oscore, 'OSCORE', value)

_re_cache = {}

class CredentialsMap(dict):
    """
    FIXME: outdated, rewrite when usable

    A CredentialsMap, for any URI template and operation, which
    security contexts are sufficient to to perform the operation on a matching
    URI.

    The same context can be used both by the server and the client, where the
    client uses the information on allowed client credentials to decide which
    credentials to present, and the information on allowed server credentials
    to decide whether the server can be trusted.

    Conversely, the server typically loads all available server credentials at
    startup, and then uses the client credentials list to decide whether to
    serve the request."""

    def load_from_dict(self, d):
        """Populate the map from a dictionary, which would typically have been
        loaded from a JSON/YAML file and needs to match the CDDL in
        credentials.cddl.

        Running this multiple times will overwriter individual entries in the
        map."""
        for k, v in d.items():
            if v is None:
                if k in self:
                    del self[k]
            else:
                self[k] = self._item_from_dict(v)
                # FIXME only works that way for OSCORE clients
                self[k].authenticated_claims = [k]

    def _item_from_dict(self, v):
        if isinstance(v, str):
            return CredentialReference(v, self)
        elif isinstance(v, dict):
            try:
                (key, value), = v.items()
            except ValueError:
                # this follows how Rust Enums are encoded in serde JSON
                raise CredentialsLoadError(
                        "Items in a credentials map must have exactly one key"
                        " (found %s)" % ("," .join(v.keys()) or "empty")
                    )

            try:
                constructor = self._class_map[key].from_item
            except KeyError:
                raise CredentialsLoadError("Unknown credential type: %s" % key)

            return constructor(value)

    _class_map = {
            'dtls': DTLS,
            'oscore': construct_oscore,
            'tlscert': TLSCert,
            'any-of': AnyOf,
            'all-of': AllOf,
            }

    @staticmethod
    def _wildcard_match(searchterm, pattern):
        if pattern not in _re_cache:
            _re_cache[pattern] = re.compile(re.escape(pattern).replace('\\*', '.*'))
        return _re_cache[pattern].fullmatch(searchterm) is not None

    # used by a client

    def credentials_from_request(self, msg):
        """Return the most specific match to a request message. Matching is
        currently based on wildcards, but not yet very well thought out."""

        uri = msg.get_request_uri()

        for i in range(1000):
            for (k, v) in sorted(self.items(), key=lambda x: len(x[0]), reverse=True):
                if self._wildcard_match(uri, k):
                    if isinstance(v, str):
                        uri = v
                        continue
                    return v
            else:
                raise CredentialsMissingError("No suitable credentials for %s" % uri)
        else:
            raise CredentialsLoadError("Search for suitable credentials for %s exceeds recursion limit")

    def ssl_client_context(self, scheme, hostinfo):
        """Return an SSL client context as configured for the given request
        scheme and hostinfo (no full message is to be processed here, as
        connections are used across requests to the same origin).

        If no credentials are configured, this returns the default SSL client
        context."""

        import ssl

        ssl_params = {}
        tlscert = self.get('%s://%s/*' % (scheme, hostinfo), None)
        if tlscert is None:
            tlscert = self.get('%s://*' % scheme, None)
        if tlscert is not None:
            ssl_params = tlscert.as_ssl_params()
        return ssl.create_default_context(**ssl_params)

    # used by a server

    def find_oscore(self, unprotected):
        # FIXME: this is not constant-time as it should be, but too much in
        # flux to warrant optimization

        # FIXME: duplicate contexts for being tried out are not supported yet.

        for item in self.values():
            if not hasattr(item, "get_oscore_context_for"):
                continue

            ctx = item.get_oscore_context_for(unprotected)
            if ctx is not None:
                return ctx

        raise KeyError()

    def find_dtls_psk(self, identity):
        # FIXME similar to find_oscore
        for (entry, item) in self.items():
            if not hasattr(item, "as_dtls_psk"):
                continue

            psk_id, psk = item.as_dtls_psk()
            if psk_id != identity:
                continue

            # FIXME is returning the entry name a sane value to later put in to
            # authenticated_claims? OSCORE does something different.
            return (psk, entry)

        raise KeyError()
