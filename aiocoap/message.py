# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from __future__ import annotations

import urllib.parse
import struct
import copy
import string
from collections import namedtuple

from . import error, optiontypes
from .numbers.codes import Code, CHANGED
from .numbers.types import Type
from .numbers.constants import DEFAULT_BLOCK_SIZE_EXP
from .options import Options
from .util import hostportjoin, hostportsplit, Sentinel, quote_nonascii
from .util.uri import quote_factory, unreserved, sub_delims
from . import interfaces

__all__ = ['Message', 'NoResponse']

# FIXME there should be a proper inteface for this that does all the urllib
# patching possibly required and works with pluggable transports. urls qualify
# if they can be parsed into the Proxy-Scheme / Uri-* structure.
coap_schemes = ['coap', 'coaps', 'coap+tcp', 'coaps+tcp', 'coap+ws', 'coaps+ws']

# Monkey patch urllib to make URL joining available in CoAP
# This is a workaround for <http://bugs.python.org/issue23759>.
urllib.parse.uses_relative.extend(coap_schemes)
urllib.parse.uses_netloc.extend(coap_schemes)

class Message(object):
    """CoAP Message with some handling metadata

    This object's attributes provide access to the fields in a CoAP message and
    can be directly manipulated.

    * Some attributes are additional data that do not round-trip through
      serialization and deserialization. They are marked as "non-roundtrippable".
    * Some attributes that need to be filled for submission of the message can
      be left empty by most applications, and will be taken care of by the
      library. Those are marked as "managed".

    The attributes are:

    * :attr:`payload`: The payload (body) of the message as bytes.
    * :attr:`mtype`: Message type (CON, ACK etc, see :mod:`.numbers.types`).
      Managed unless set by the application.
    * :attr:`code`: The code (either request or response code), see
      :mod:`.numbers.codes`.
    * :attr:`opt`: A container for the options, see :class:`.options.Options`.

    * :attr:`mid`: The message ID. Managed by the :class:`.Context`.
    * :attr:`token`: The message's token as bytes. Managed by the :class:`.Context`.
    * :attr:`remote`: The socket address of the other side, managed by the
      :class:`.protocol.Request` by resolving the ``.opt.uri_host`` or
      ``unresolved_remote``, or the :class:`.Responder` by echoing the incoming
      request's. Follows the :class:`.interfaces.EndpointAddress` interface.
      Non-roundtrippable.

      While a message has not been transmitted, the property is managed by the
      :class:`.Message` itself using the :meth:`.set_request_uri()` or the
      constructor `uri` argument.

    * :attr:`request`: The request to which an incoming response message
      belongs; only available at the client. Managed by the
      :class:`.interfaces.RequestProvider` (typically a :class:`.Context`).

    These properties are still available but deprecated:

    * requested_*: Managed by the :class:`.protocol.Request` a response results
      from, and filled with the request's URL data. Non-roundtrippable.

    * unresolved_remote: ``host[:port]`` (strictly speaking; hostinfo as in a
      URI) formatted string. If this attribute is set, it overrides
      ``.RequestManageropt.uri_host`` (and ``-_port``) when it comes to filling the
      ``remote`` in an outgoing request.

      Use this when you want to send a request with a host name that would not
      normally resolve to the destination address. (Typically, this is used for
      proxying.)

    Options can be given as further keyword arguments at message construction
    time. This feature is experimental, as future message parameters could
    collide with options.


    The four messages involved in an exchange
    -----------------------------------------

    ::

        Requester                                  Responder

        +-------------+                          +-------------+
        | request msg |  ---- send request --->  | request msg |
        +-------------+                          +-------------+
                                                       |
                                                  processed into
                                                       |
                                                       v
        +-------------+                          +-------------+
        | response m. |  <--- send response ---  | response m. |
        +-------------+                          +-------------+


    The above shows the four message instances involved in communication
    between an aiocoap client and server process. Boxes represent instances of
    Message, and the messages on the same line represent a single CoAP as
    passed around on the network. Still, they differ in some aspects:

        * The requested URI will look different between requester and responder
          if the requester uses a host name and does not send it in the message.
        * If the request was sent via multicast, the response's requested URI
          differs from the request URI because it has the responder's address
          filled in. That address is not known at the responder's side yet, as
          it is typically filled out by the network stack.
        * It is yet unclear whether the response's URI should contain an IP
          literal or a host name in the unicast case if the Uri-Host option was
          not sent.
        * Properties like Message ID and token will differ if a proxy was
          involved.
        * Some options or even the payload may differ if a proxy was involved.
    """

    def __init__(self, *, mtype=None, mid=None, code=None, payload=b'', token=b'', uri=None, **kwargs):
        self.version = 1
        if mtype is None:
            # leave it unspecified for convenience, sending functions will know what to do
            self.mtype = None
        else:
            self.mtype = Type(mtype)
        self.mid = mid
        if code is None:
            # as above with mtype
            self.code = None
        else:
            self.code = Code(code)
        self.token = token
        self.payload = payload
        self.opt = Options()

        self.remote = None

        # deprecation error, should go away roughly after 0.2 release
        if self.payload is None:
            raise TypeError("Payload must not be None. Use empty string instead.")

        if uri:
            self.set_request_uri(uri)

        for k, v in kwargs.items():
            setattr(self.opt, k, v)

    def __repr__(self):
        return "<aiocoap.Message at %#x: %s %s (%s, %s) remote %s%s%s>"%(
                id(self),
                self.mtype if self.mtype is not None else "no mtype,",
                self.code,
                "MID %s" % self.mid if self.mid is not None else "no MID",
                "token %s" % self.token.hex() if self.token else "empty token",
                self.remote,
                ", %s option(s)"%len(self.opt._options) if self.opt._options else "",
                ", %s byte(s) payload"%len(self.payload) if self.payload else ""
                )

    def copy(self, **kwargs):
        """Create a copy of the Message. kwargs are treated like the named
        arguments in the constructor, and update the copy."""
        # This is part of moving messages in an "immutable" direction; not
        # necessarily hard immutable. Let's see where this goes.

        new = type(self)(
                mtype=kwargs.pop('mtype', self.mtype),
                mid=kwargs.pop('mid', self.mid),
                code=kwargs.pop('code', self.code),
                payload=kwargs.pop('payload', self.payload),
                token=kwargs.pop('token', self.token),
                )
        new.remote = kwargs.pop('remote', self.remote)
        new.opt = copy.deepcopy(self.opt)

        if 'uri' in kwargs:
            new.set_request_uri(kwargs.pop('uri'))

        for k, v in kwargs.items():
            setattr(new.opt, k, v)

        return new

    @classmethod
    def decode(cls, rawdata, remote=None):
        """Create Message object from binary representation of message."""
        try:
            (vttkl, code, mid) = struct.unpack('!BBH', rawdata[:4])
        except struct.error:
            raise error.UnparsableMessage("Incoming message too short for CoAP")
        version = (vttkl & 0xC0) >> 6
        if version != 1:
            raise error.UnparsableMessage("Fatal Error: Protocol Version must be 1")
        mtype = (vttkl & 0x30) >> 4
        token_length = (vttkl & 0x0F)
        msg = Message(mtype=mtype, mid=mid, code=code)
        msg.token = rawdata[4:4 + token_length]
        msg.payload = msg.opt.decode(rawdata[4 + token_length:])
        msg.remote = remote
        return msg

    def encode(self):
        """Create binary representation of message from Message object."""
        if self.code is None or self.mtype is None or self.mid is None:
            raise TypeError("Fatal Error: Code, Message Type and Message ID must not be None.")
        rawdata = bytes([(self.version << 6) + ((self.mtype & 0x03) << 4) + (len(self.token) & 0x0F)])
        rawdata += struct.pack('!BH', self.code, self.mid)
        rawdata += self.token
        rawdata += self.opt.encode()
        if len(self.payload) > 0:
            rawdata += bytes([0xFF])
            rawdata += self.payload
        return rawdata

    def get_cache_key(self, ignore_options=()):
        """Generate a hashable and comparable object (currently a tuple) from
        the message's code and all option values that are part of the cache key
        and not in the optional list of ignore_options (which is the list of
        option numbers that are not technically NoCacheKey but handled by the
        application using this method).

        >>> from aiocoap.numbers import GET
        >>> m1 = Message(code=GET)
        >>> m2 = Message(code=GET)
        >>> m1.opt.uri_path = ('s', '1')
        >>> m2.opt.uri_path = ('s', '1')
        >>> m1.opt.size1 = 10 # the only no-cache-key option in the base spec
        >>> m2.opt.size1 = 20
        >>> m1.get_cache_key() == m2.get_cache_key()
        True
        >>> m2.opt.etag = b'000'
        >>> m1.get_cache_key() == m2.get_cache_key()
        False
        >>> from aiocoap.numbers.optionnumbers import OptionNumber
        >>> ignore = [OptionNumber.ETAG]
        >>> m1.get_cache_key(ignore) == m2.get_cache_key(ignore)
        True
        """

        options = []

        for option in self.opt.option_list():
            if option.number in ignore_options or (option.number.is_safetoforward() and option.number.is_nocachekey()):
                continue
            options.append((option.number, option.value))

        return (self.code, tuple(options))

    #
    # splitting and merging messages into and from message blocks
    #

    def _extract_block(self, number, size_exp, max_bert_size):
        """Extract block from current message."""
        if size_exp == 7:
            start = number * 1024
            size = 1024 * max_bert_size // 1024
        else:
            size = 2 ** (size_exp + 4)
            start = number * size

        if start >= len(self.payload):
            raise error.BadRequest("Block request out of bounds")

        end = start + size if start + size < len(self.payload) else len(self.payload)
        more = True if end < len(self.payload) else False

        payload = self.payload[start:end]
        blockopt = (number, more, size_exp)

        if self.code.is_request():
            return self.copy(
                    payload=payload,
                    mid=None,
                    block1=blockopt
                    )
        else:
            return self.copy(
                    payload=payload,
                    mid=None,
                    block2=blockopt
                    )

    def _append_request_block(self, next_block):
        """Modify message by appending another block"""
        if not self.code.is_request():
            raise ValueError("_append_request_block only works on requests.")

        block1 = next_block.opt.block1
        if block1.more:
            if len(next_block.payload) == block1.size:
                pass
            elif block1.size_exponent == 7 and \
                    len(next_block.payload) % block1.size == 0:
                pass
            else:
                raise error.BadRequest("Payload size does not match Block1")
        if block1.start == len(self.payload):
            self.payload += next_block.payload
            self.opt.block1 = block1
            self.token = next_block.token
            self.mid = next_block.mid
            if not block1.more and next_block.opt.block2 is not None:
                self.opt.block2 = next_block.opt.block2
        else:
            # possible extension point: allow messages with "gaps"; then
            # ValueError would only be raised when trying to overwrite an
            # existing part; it is doubtful though that the blockwise
            # specification even condones such behavior.
            raise ValueError()

    def _append_response_block(self, next_block):
        """Append next block to current response message.
           Used when assembling incoming blockwise responses."""
        if not self.code.is_response():
            raise ValueError("_append_response_block only works on responses.")

        block2 = next_block.opt.block2
        if not block2.is_valid_for_payload_size(len(next_block.payload)):
            raise error.UnexpectedBlock2("Payload size does not match Block2")
        if block2.start != len(self.payload):
            # Does not need to be implemented as long as the requesting code
            # sequentially clocks out data
            raise error.NotImplemented()

        if next_block.opt.etag != self.opt.etag:
            raise error.ResourceChanged()

        self.payload += next_block.payload
        self.opt.block2 = block2
        self.token = next_block.token
        self.mid = next_block.mid

    def _generate_next_block2_request(self, response):
        """Generate a sub-request for next response block.

        This method is used by client after receiving blockwise response from
        server with "more" flag set."""

        # Note: response here is the assembled response, but (due to
        # _append_response_block's workings) it carries the Block2 option of
        # the last received block.

        next_after_received = len(response.payload) // response.opt.block2.size
        blockopt = optiontypes.BlockOption.BlockwiseTuple(
                next_after_received, False, response.opt.block2.size_exponent)

        # has been checked in assembly, just making sure
        assert blockopt.start == len(response.payload)

        blockopt = blockopt.reduced_to(response.remote.maximum_block_size_exp)

        return self.copy(
                payload=b"",
                mid=None,
                token=None,
                block2=blockopt,
                block1=None,
                observe=None
                )

    def _generate_next_block1_response(self):
        """Generate a response to acknowledge incoming request block.

        This method is used by server after receiving blockwise request from
        client with "more" flag set."""
        response = Message(code=CHANGED, token=self.token)
        response.remote = self.remote
        if self.opt.block1.block_number == 0 and self.opt.block1.size_exponent > DEFAULT_BLOCK_SIZE_EXP:
            new_size_exponent = DEFAULT_BLOCK_SIZE_EXP
            response.opt.block1 = (0, True, new_size_exponent)
        else:
            response.opt.block1 = (self.opt.block1.block_number, True, self.opt.block1.size_exponent)
        return response

    #
    # the message in the context of network and addresses
    #


    def get_request_uri(self, *, local_is_server=False):
        """The absolute URI this message belongs to.

        For requests, this is composed from the options (falling back to the
        remote). For responses, this is largely taken from the original request
        message (so far, that could have been trackecd by the requesting
        application as well), but -- in case of a multicast request -- with the
        host replaced by the responder's endpoint details.

        This implements Section 6.5 of RFC7252.

        By default, these values are only valid on the client. To determine a
        message's request URI on the server, set the local_is_server argument
        to True. Note that determining the request URI on the server is brittle
        when behind a reverse proxy, may not be possible on all platforms, and
        can only be applied to a request message in a renderer (for the
        response message created by the renderer will only be populated when it
        gets transmitted; simple manual copying of the request's remote to the
        response will not magically make this work, for in the very case where
        the request and response's URIs differ, that would not catch the
        difference and still report the multicast address, while the actual
        sending address will only be populated by the operating system later).
        """

        # maybe this function does not belong exactly *here*, but it belongs to
        # the results of .request(message), which is currently a message itself.

        if self.code.is_response():
            refmsg = self.request

            if refmsg.remote.is_multicast:
                if local_is_server:
                    multicast_netloc_override = self.remote.hostinfo_local
                else:
                    multicast_netloc_override = self.remote.hostinfo
            else:
                multicast_netloc_override = None
        else:
            refmsg = self
            multicast_netloc_override = None

        proxyuri = refmsg.opt.proxy_uri
        if proxyuri is not None:
            return proxyuri

        scheme = refmsg.opt.proxy_scheme or refmsg.remote.scheme
        query = refmsg.opt.uri_query or ()
        path = refmsg.opt.uri_path

        if multicast_netloc_override is not None:
            netloc = multicast_netloc_override
        else:
            if local_is_server:
                netloc = refmsg.remote.hostinfo_local
            else:
                netloc = refmsg.remote.hostinfo

            if refmsg.opt.uri_host is not None or \
                    refmsg.opt.uri_port is not None:

                host, port = hostportsplit(netloc)

                host = refmsg.opt.uri_host or host
                port = refmsg.opt.uri_port or port

                # FIXME: This sounds like it should be part of
                # hpostportjoin/-split
                escaped_host = quote_nonascii(host)

                # FIXME: "If host is not valid reg-name / IP-literal / IPv4address,
                # fail"

                netloc = hostportjoin(escaped_host, port)

        # FIXME this should follow coap section 6.5 more closely
        query = "&".join(_quote_for_query(q) for q in query)
        path = ''.join("/" + _quote_for_path(p) for p in path) or '/'

        fragment = None
        params = "" # are they not there at all?

        # Eases debugging, for when thy raise from urunparse you won't know
        # which it was
        assert scheme is not None
        assert netloc is not None
        return urllib.parse.urlunparse((scheme, netloc, path, params, query, fragment))

    def set_request_uri(self, uri, *, set_uri_host=True):
        """Parse a given URI into the uri_* fields of the options.

        The remote does not get set automatically; instead, the remote data is
        stored in the uri_host and uri_port options. That is because name resolution
        is coupled with network specifics the protocol will know better by the
        time the message is sent. Whatever sends the message, be it the
        protocol itself, a proxy wrapper or an alternative transport, will know
        how to handle the information correctly.

        When ``set_uri_host=False`` is passed, the host/port is stored in the
        ``unresolved_remote`` message property instead of the uri_host option;
        as a result, the unresolved host name is not sent on the wire, which
        breaks virtual hosts but makes message sizes smaller.

        This implements Section 6.4 of RFC7252.
        """

        parsed = urllib.parse.urlparse(uri)

        if parsed.fragment:
            raise ValueError("Fragment identifiers can not be set on a request URI")

        if parsed.scheme not in coap_schemes:
            self.opt.proxy_uri = uri
            return

        if parsed.username or parsed.password:
            raise ValueError("User name and password not supported.")

        if parsed.path not in ('', '/'):
            self.opt.uri_path = [urllib.parse.unquote(x) for x in parsed.path.split('/')[1:]]
        else:
            self.opt.uri_path = []
        if parsed.query:
            self.opt.uri_query = [urllib.parse.unquote(x) for x in parsed.query.split('&')]
        else:
            self.opt.uri_query = []

        self.remote = UndecidedRemote(parsed.scheme, parsed.netloc)

        is_ip_literal = parsed.netloc.startswith('[') or (
                parsed.hostname.count('.') == 3 and
                all(c in '0123456789.' for c in parsed.hostname) and
                all(int(x) <= 255 for x in parsed.hostname.split('.')))

        if set_uri_host and not is_ip_literal:
            self.opt.uri_host = urllib.parse.unquote(parsed.hostname).translate(_ascii_lowercase)

    # Deprecated accessors to moved functionality

    @property
    def unresolved_remote(self):
        return self.remote.hostinfo

    @unresolved_remote.setter
    def unresolved_remote(self, value):
        # should get a big fat deprecation warning
        if value is None:
            self.remote = UndecidedRemote('coap', None)
        else:
            self.remote = UndecidedRemote('coap', value)

    @property
    def requested_scheme(self):
        if self.code.is_request():
            return self.remote.scheme
        else:
            return self.request.requested_scheme

    @requested_scheme.setter
    def requested_scheme(self, value):
        self.remote = UndecidedRemote(value, self.remote.hostinfo)

    @property
    def requested_proxy_uri(self):
        return self.request.opt.proxy_uri

    @property
    def requested_hostinfo(self):
        return self.request.opt.uri_host or self.request.unresolved_remote

    @property
    def requested_path(self):
        return self.request.opt.uri_path

    @property
    def requested_query(self):
        return self.request.opt.uri_query

class UndecidedRemote(
        namedtuple("_UndecidedRemote", ("scheme", "hostinfo")),
        interfaces.EndpointAddress
        ):
    """Remote that is set on messages that have not been sent through any any
    transport.

    It describes scheme, hostname and port that were set in
    :meth:`.set_request_uri()` or when setting a URI per Message constructor.

    * :attr:`scheme`: The scheme string
    * :attr:`hostinfo`: The authority component of the URI, as it would occur
      in the URI.
    """

    @classmethod
    def from_pathless_uri(cls, uri: str) -> UndecidedRemote:
        """Create an UndecidedRemote for a given URI that has no query, path,
        fragment or other components not expressed in an UndecidedRemote

        >>> from aiocoap.message import UndecidedRemote
        >>> UndecidedRemote.from_pathless_uri("coap://localhost")
        UndecidedRemote(scheme='coap', hostinfo='localhost')
        >>> UndecidedRemote.from_pathless_uri("coap+tcp://[::1]:1234")
        UndecidedRemote(scheme='coap+tcp', hostinfo='[::1]:1234')
        """

        parsed = urllib.parse.urlparse(uri)

        if parsed.username or parsed.password:
            raise ValueError("User name and password not supported.")

        if parsed.path not in ('', '/') or parsed.query or parsed.fragment:
            raise ValueError("Paths and query and fragment can not be set on an UndecidedRemote")

        return cls(parsed.scheme, parsed.netloc)

_ascii_lowercase = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

_quote_for_path = quote_factory(unreserved + sub_delims + ':@')
_quote_for_query = quote_factory(unreserved + "".join(c for c in sub_delims if c != '&') + ':@/?')

#: Result that can be returned from a render method instead of a Message when
#: due to defaults (eg. multicast link-format queries) or explicit
#: configuration (eg. the No-Response option), no response should be sent at
#: all. Note that per RFC7967 section 2, an ACK is still sent to a CON
#: request.
#:
#: Depercated; set the no_response option on a regular response instead (see
#: :meth:`.interfaces.Resource.render` for details).
NoResponse = Sentinel("NoResponse")
