# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import urllib.parse
import struct
import copy
import ipaddress

from . import error
from .numbers import *
from .options import Options

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
    * :attr:`remote`: The socket address of the  side, managed by the
      :class:`.protocol.Request` by resolving the ``.opt.uri_host``, or the
      :class:`.Responder` by echoing the incoming request's. (If you choose to
      set this explicitly set this, make sure not to set incomplete IPv6
      address tuples, as they can be sent but don't compare equally with the
      responses). Non-roundtrippable.

    * requested_*: Managed by the :class:`.protocol.Request` a response results
      from, and filled with the request's URL data. Non-roundtrippable.

    * :attr:`prepath`, :attr:`postpath`: Not sure, will probably go away when
      resources are overhauled. Non-roundtrippable.
    """

    def __init__(self, mtype=None, mid=None, code=EMPTY, payload=b'', token=b''):
        self.version = 1
        if mtype is None:
            # leave it unspecified for convenience, sending functions will know what to do
            self.mtype = None
        else:
            self.mtype = Type(mtype)
        self.mid = mid
        self.code = Code(code)
        self.token = token
        self.payload = payload
        self.opt = Options()

        self.remote = None
        self.prepath = None
        self.postpath = None

        # attributes that indicate which request path the response belongs to.
        # their main purpose is allowing .get_request_uri() to work smoothly, a
        # feature that is required to resolve links relative to the message.
        #
        # path and query are stored as lists, as they would be accessed for
        # example by self.opt.uri_path
        self.requested_proxy_uri = None
        self.requested_scheme = None
        self.requested_host = None
        self.requested_port = None
        self.requested_path = None
        self.requested_query = None

        if self.payload is None:
            raise TypeError("Payload must not be None. Use empty string instead.")

    def __repr__(self):
        return "<aiocoap.Message at %#x: %s %s (ID %r, token %r) remote %s%s%s>"%(
                id(self),
                self.mtype,
                self.code,
                self.mid,
                self.token,
                self.remote,
                ", %s option(s)"%len(self.opt._options) if self.opt._options else "",
                ", %s byte(s) payload"%len(self.payload) if self.payload else ""
                )

    @classmethod
    def decode(cls, rawdata, remote=None):
        """Create Message object from binary representation of message."""
        try:
            (vttkl, code, mid) = struct.unpack('!BBH', rawdata[:4])
        except struct.error:
            raise error.UnparsableMessage("Incoming message too short for CoAP")
        version = (vttkl & 0xC0) >> 6
        if version is not 1:
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
        if self.mtype is None or self.mid is None:
            raise TypeError("Fatal Error: Message Type and Message ID must not be None.")
        rawdata = bytes([(self.version << 6) + ((self.mtype & 0x03) << 4) + (len(self.token) & 0x0F)])
        rawdata += struct.pack('!BH', self.code, self.mid)
        rawdata += self.token
        rawdata += self.opt.encode()
        if len(self.payload) > 0:
            rawdata += bytes([0xFF])
            rawdata += self.payload
        return rawdata

    #
    # splitting and merging messages into and from message blocks
    #

    def _extract_block(self, number, size_exp):
        """Extract block from current message."""
        size = 2 ** (size_exp + 4)
        start = number * size
        if start < len(self.payload):
            end = start + size if start + size < len(self.payload) else len(self.payload)
            block = copy.deepcopy(self)
            block.payload = block.payload[start:end]
            block.mid = None
            more = True if end < len(self.payload) else False
            if block.code.is_request():
                block.opt.block1 = (number, more, size_exp)
            else:
                block.opt.block2 = (number, more, size_exp)
            return block

    def _append_request_block(self, next_block):
        """Modify message by appending another block"""
        if not self.code.is_request():
            raise ValueError("_append_request_block only works on requests.")

        block1 = next_block.opt.block1
        if block1.start == len(self.payload):
            self.payload += next_block.payload
            self.opt.block1 = block1
            self.token = next_block.token
            self.mid = next_block.mid
        else:
            raise error.NotImplemented()

    def _append_response_block(self, next_block):
        """Append next block to current response message.
           Used when assembling incoming blockwise responses."""
        if not self.code.is_response():
            raise ValueError("_append_response_block only works on responses.")

        block2 = next_block.opt.block2
        if block2.start != len(self.payload):
            raise error.NotImplemented()

        if next_block.opt.etag != self.opt.etag:
            raise error.ResourceChanged()

        self.payload += next_block.payload
        self.opt.block2 = block2
        self.token = next_block.token
        self.mid = next_block.mid

    def _generate_next_block2_request(self, response):
        """Generate a request for next response block.

        This method is used by client after receiving blockwise response from
        server with "more" flag set."""
        request = copy.deepcopy(self)
        request.payload = b""
        request.mid = None
        if response.opt.block2.block_number == 0 and response.opt.block2.size_exponent > DEFAULT_BLOCK_SIZE_EXP:
            new_size_exponent = DEFAULT_BLOCK_SIZE_EXP
            new_block_number = 2 ** (response.opt.block2.size_exponent - new_size_exponent)
            request.opt.block2 = (new_block_number, False, new_size_exponent)
        else:
            request.opt.block2 = (response.opt.block2.block_number + 1, False, response.opt.block2.size_exponent)
        del request.opt.block1
        del request.opt.observe
        return request

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

    @staticmethod
    def _build_request_uri(scheme, host, port, path, query):
        """Assemble path components as found in CoAP options into a URL. Helper
        for :meth:`get_request_uri`."""

        if ':' in host:
            host = '[%s]'%host

        if port is None:
            netloc = host
        else:
            netloc = "%s:%d"%(host, port)

        # FIXME this should follow coap section 6.5 more closely
        query = "?" + "&".join(query) if query else ""
        path = '/'.join(("",) + path) or '/'

        fragment = None
        params = "" # are they not there at all?

        return urllib.parse.urlunparse((scheme, netloc, path, params, query, fragment))

    def get_request_uri(self):
        """The absolute URI this message belongs to.

        For requests, this is composed from the options (falling back to the
        remote). For responses, this is stored by the Request object not only
        to preserve the request information (which could have been kept by the
        requesting application), but also because the Request can know about
        multicast responses (which would update the host component) and
        redirects (FIXME do they exist?)."""

        # maybe this function does not belong exactly *here*, but it belongs to
        # the results of .request(message), which is currently a message itself.

        if self.code.is_response():
            proxyuri = self.requested_proxy_uri
            scheme = self.requested_scheme or 'coap'
            query = self.requested_query
            path = self.requested_path
        else:
            proxyuri = self.opt.proxy_uri
            scheme = self.opt.get_option(OptionNumber.PROXY_SCHEME) or 'coap'
            query = self.opt.get_option(OptionNumber.URI_QUERY) or ()
            path = self.opt.uri_path

        if self.code.is_response() and self.requested_host is not None:
            host = self.requested_host
        elif self.code.is_request() and self.opt.uri_host is not None:
            host = self.opt.uri_host
        else:
            host = self.remote[0]

        if self.code.is_response() and self.requested_port is not None:
            port = self.requested_port
        elif self.code.is_request() and self.opt.uri_port is not None:
            port = self.opt.uri_port
        elif self.remote is not None:
            port = self.remote[1]
            if port == COAP_PORT:
                # don't explicitly add port if not required
                port = None
        else:
            port = None

        if proxyuri is not None:
            return proxyuri

        return self._build_request_uri(scheme, host, port, path, query)

    def set_request_uri(self, uri):
        """Parse a given URI into the uri_* fields of the options.

        The remote does not get set automatically; instead, the remote data is
        stored in the uri_host and uri_port options. That is because name resolution
        is coupled with network specifics the protocol will know better by the
        time the message is sent. Whatever sends the message, be it the
        protocol itself, a proxy wrapper or an alternative transport, will know
        how to handle the information correctly."""

        parsed = urllib.parse.urlparse(uri, allow_fragments=False)

        if parsed.scheme != 'coap':
            self.opt.proxy_uri = uri
            return

        if parsed.username or parsed.password:
            raise ValueError("User name and password not supported.")

        # FIXME as with get_request_uri, this hould do encoding/decoding and section 6.5 etc

        if parsed.path not in ('', '/'):
            self.opt.uri_path = parsed.path.split('/')[1:]
        else:
            self.opt.uri_path = []
        if parsed.query:
            self.opt.uri_query = parsed.query.split('&')
        else:
            self.opt.uri_query = []

        if parsed.port:
            self.opt.uri_port = parsed.port
        self.opt.uri_host = parsed.hostname

    def has_multicast_remote(self):
        """Return True if the message's remote needs to be considered a multicast remote."""
        address = ipaddress.ip_address(self.remote[0])
        return address.is_multicast
