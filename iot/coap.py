'''
Created on 08-09-2012

@author: Maciej Wasilak
'''
import random
import copy
import struct
import collections
from itertools import chain
import binascii
import ipaddress
import urllib

import asyncio

from queuewithend import QueueWithEnd

import logging
# log levels used:
# * debug is for things that occur even under perfect conditions.
# * info is for things that are well expected, but might be interesting during
#   testing a network of nodes and not debugging the library. (timeouts,
#   retransmissions, pings)
# * warning is for everything that indicates a malbehaved client. (these don't
#   necessarily indicate a client bug, though; things like requesting a
#   nonexistent block can just as well happen when a resource's content has
#   changed between blocks).

import iot.error
from enum import IntEnum
from .util import ExtensibleIntEnum

COAP_PORT = 5683
"""The IANA-assigned standard port for COAP services."""

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | ACK_TIMEOUT       | 2 seconds     |
#   | ACK_RANDOM_FACTOR | 1.5           |
#   | MAX_RETRANSMIT    | 4             |
#   | NSTART            | 1             |
#   | DEFAULT_LEISURE   | 5 seconds     |
#   | PROBING_RATE      | 1 Byte/second |
#   +-------------------+---------------+

ACK_TIMEOUT = 2.0
"""The time, in seconds, to wait for an acknowledgement of a
confirmable message. The inter-transmission time doubles
for each retransmission."""

ACK_RANDOM_FACTOR = 1.5
"""Timeout multiplier for anti-synchronization."""

MAX_RETRANSMIT = 4
"""The number of retransmissions of confirmable messages to
non-multicast endpoints before the infrastructure assumes no
acknowledgement will be received."""

NSTART = 1
"""Maximum number of simultaneous outstanding interactions
   that endpoint maintains to a given server (including proxies)"""

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | MAX_TRANSMIT_SPAN |          45 s |
#   | MAX_TRANSMIT_WAIT |          93 s |
#   | MAX_LATENCY       |         100 s |
#   | PROCESSING_DELAY  |           2 s |
#   | MAX_RTT           |         202 s |
#   | EXCHANGE_LIFETIME |         247 s |
#   | NON_LIFETIME      |         145 s |
#   +-------------------+---------------+

MAX_TRANSMIT_SPAN = ACK_TIMEOUT * (2 ** MAX_RETRANSMIT - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to its last retransmission."""

MAX_TRANSMIT_WAIT = ACK_TIMEOUT * (2 ** (MAX_RETRANSMIT + 1) - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to the time when the sender gives up on
receiving an acknowledgement or reset."""

MAX_LATENCY = 100.0
"""Maximum time a datagram is expected to take from the start
of its transmission to the completion of its reception."""

PROCESSING_DELAY = ACK_TIMEOUT
""""Time a node takes to turn around a
confirmable message into an acknowledgement."""

MAX_RTT = 2 * MAX_LATENCY + PROCESSING_DELAY
"""Maximum round-trip time."""

EXCHANGE_LIFETIME = MAX_TRANSMIT_SPAN + MAX_RTT
"""time from starting to send a confirmable
 message to the time when an acknowledgement is no longer expected,
i.e. message layer information about the message exchange can be purged"""

DEFAULT_BLOCK_SIZE_EXP = 6 # maximum block size 1024
"""Default size exponent for blockwise transfers."""

EMPTY_ACK_DELAY = 0.1
"""After this time protocol sends empty ACK, and separate response"""

REQUEST_TIMEOUT = MAX_TRANSMIT_WAIT
"""Time after which server assumes it won't receive any answer.
   It is not defined by IETF documents.
   For human-operated devices it might be preferable to set some small value
   (for example 10 seconds)
   For M2M it's application dependent."""

DEFAULT_LEISURE = 5

MULTICAST_REQUEST_TIMEOUT = REQUEST_TIMEOUT + DEFAULT_LEISURE

class Type(IntEnum):
    CON = 0 # Confirmable
    NON = 1 # Non-confirmable
    ACK = 2 # Acknowledgement
    RST = 3 # Reset

CON, NON, ACK, RST = Type.CON, Type.NON, Type.ACK, Type.RST

class Code(ExtensibleIntEnum):
    EMPTY = 0
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4
    CREATED = 65
    DELETED = 66
    VALID = 67
    CHANGED = 68
    CONTENT = 69
    CONTINUE = 95
    BAD_REQUEST = 128
    UNAUTHORIZED = 129
    BAD_OPTION = 130
    FORBIDDEN = 131
    NOT_FOUND = 132
    METHOD_NOT_ALLOWED = 133
    NOT_ACCEPTABLE = 134
    REQUEST_ENTITY_INCOMPLETE = 136
    PRECONDITION_FAILED = 140
    REQUEST_ENTITY_TOO_LARGE = 141
    UNSUPPORTED_MEDIA_TYPE = 143
    INTERNAL_SERVER_ERROR = 160
    NOT_IMPLEMENTED = 161
    BAD_GATEWAY = 162
    SERVICE_UNAVAILABLE = 163
    GATEWAY_TIMEOUT = 164
    PROXYING_NOT_SUPPORTED = 165

    def is_request(code):
        return True if (code >= 1 and code < 32) else False


    def is_response(code):
        return True if (code >= 64 and code < 192) else False


    def is_successful(code):
        return True if (code >= 64 and code < 96) else False

    @property
    def dotted(self):
        return "%d.%02d"%divmod(self, 32)

    @property
    def name_printable(self):
        return self.name.replace('_', ' ').title()

    def __str__(self):
        if self.is_request():
            return self.name
        elif self.is_response():
            return "%s %s"%(self.dotted, self.name_printable)
        else:
            return "<Code %d>"%self

    name = property(lambda self: self._name if hasattr(self, "_name") else "(unknown)", lambda self, value: setattr(self, "_name", value))

for k in vars(Code):
    if isinstance(getattr(Code, k), Code):
        locals()[k] = getattr(Code, k)

#=============================================================================
# coap-18, block-14, observe-11
#=============================================================================
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# | No. | C | U | N | R | Name           | Format     | Length | Default     |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# |   1 | x |   |   | x | If-Match       | opaque     | 0-8    | (none)      |
# |   3 | x | x | - |   | Uri-Host       | string     | 1-255  | (see below) |
# |   4 |   |   |   | x | ETag           | opaque     | 1-8    | (none)      |
# |   5 | x |   |   |   | If-None-Match  | empty      | 0      | (none)      |
# |   6 |   | x |   |   | Observe        | empty/uint | ?      | (none)      |
# |   7 | x | x | - |   | Uri-Port       | uint       | 0-2    | (see below) |
# |   8 |   |   |   | x | Location-Path  | string     | 0-255  | (none)      |
# |  11 | x | x | - | x | Uri-Path       | string     | 0-255  | (none)      |
# |  12 |   |   |   |   | Content-Format | uint       | 0-2    | (none)      |
# |  14 |   | x |   |   | Max-Age        | uint       | 0-4    | 60          |
# |  15 | x | x | - | x | Uri-Query      | string     | 0-255  | (none)      |
# |  17 | x |   |   |   | Accept         | uint       | 0-2    | (none)      |
# |  20 |   |   |   | x | Location-Query | string     | 0-255  | (none)      |
# |  23 | x | x | - | - | Block2         | uint       | 0-3    | (see below) |
# |  27 | x | x | - | - | Block1         | uint       | 0-3    | (see below) |
# |  28 |   |   | x |   | Size2          | uint       | 0-4    | (none)      |
# |  35 | x | x | - |   | Proxy-Uri      | string     | 1-1034 | (none)      |
# |  39 | x | x | - |   | Proxy-Scheme   | string     | 1-255  | (none)      |
# |  60 |   |   | x |   | Size1          | uint       | 0-4    | (none)      |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
#=============================================================================
#
# This table should serve as a reference only. It does not confirm that
# txThings conforms to the documents above
#

class OptionNumber(ExtensibleIntEnum):
    IF_MATCH = 1
    URI_HOST = 3
    ETAG = 4
    IF_NONE_MATCH = 5
    OBSERVE = 6
    URI_PORT = 7
    LOCATION_PATH = 8
    URI_PATH = 11
    CONTENT_FORMAT = 12
    MAX_AGE = 14
    URI_QUERY = 15
    ACCEPT = 17
    LOCATION_QUERY = 20
    BLOCK2 = 23
    BLOCK1 = 27
    SIZE2 = 28
    PROXY_URI = 35
    PROXY_SCHEME = 39
    SIZE1 = 60

    def is_critical(self):
        return self & 0x01 == 0x01

    def is_elective(self):
        return not self.is_critical()

    def is_unsafe(self):
        return self & 0x02 == 0x02

    def is_safetoforward(self):
        return not self.is_unsafe()

    def is_nocachekey(self):
        return self & 0x1e != 0x1c

    def is_cachekey(self):
        return not self.is_nocachekey()

    def _get_format(self):
        if hasattr(self, "_format"):
            return self._format
        else:
            return OpaqueOption

    def _set_format(self, value):
        self._format = value

    format = property(_get_format, _set_format)

    def create_option(self, decode=None, value=None):
        """Return an Option element of the appropriate class from this option
        number.

        An initial value may be set using the decode or value options, and will
        be fed to the resulting object's decode method or value property,
        respectively."""
        option = self.format(self)
        if decode is not None:
            option.decode(decode)
        if value is not None:
            option.value = value
        return option

media_types = {0: 'text/plain',
               40: 'application/link-format',
               41: 'application/xml',
               42: 'application/octet-stream',
               47: 'application/exi',
               50: 'application/json'}
"""A map from CoAP-assigned integral codes to Internet media type descriptions."""

media_types_rev = {v:k for k, v in media_types.items()}

def is_multicast_remote(remote):
    """Return True if the described remote (typically a (host, port) tuple) needs to be considered a multicast remote."""
    host = remote[0]
    address = ipaddress.ip_address(remote[0])
    return address.is_multicast

class Message(object):
    """A CoAP Message."""

    def __init__(self, mtype=None, mid=None, code=EMPTY, payload=b'', token=b''):
        self.version = 1
        self.mtype = Type(mtype)
        self.mid = mid
        self.code = Code(code)
        self.token = token
        self.payload = payload
        self.opt = Options()

        self.response_type = None
        self.remote = None
        self.prepath = None
        self.postpath = None

        # attributes that indicate which request path the response belongs to.
        # their main purpose is allowing .get_request_uri() to work smoothly, a
        # feature that is required to resolve links relative to the message.
        #
        # both are stored as lists, as they would be accessed for example by
        # self.opt.uri_path
        self.requested_path = None
        self.requested_query = None

        if self.payload is None:
            raise TypeError("Payload must not be None. Use empty string instead.")

    @classmethod
    def decode(cls, rawdata, remote=None, protocol=None):
        """Create Message object from binary representation of message."""
        try:
            (vttkl, code, mid) = struct.unpack('!BBH', rawdata[:4])
        except struct.error:
            raise iot.error.UnparsableMessage("Incoming message too short for CoAP")
        version = (vttkl & 0xC0) >> 6
        if version is not 1:
            raise iot.error.UnparsableMessage("Fatal Error: Protocol Version must be 1")
        mtype = (vttkl & 0x30) >> 4
        token_length = (vttkl & 0x0F)
        msg = Message(mtype=mtype, mid=mid, code=code)
        msg.token = rawdata[4:4 + token_length]
        msg.payload = msg.opt.decode(rawdata[4 + token_length:])
        msg.remote = remote
        msg.protocol = protocol
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

    def extractBlock(self, number, size_exp):
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

    def appendRequestBlock(self, next_block):
        """Append next block to current request message.
           Used when assembling incoming blockwise requests."""
        if self.code.is_request():
            block1 = next_block.opt.block1
            if block1.block_number * (2 ** (block1.size_exponent + 4)) == len(self.payload):
                self.payload += next_block.payload
                self.opt.block1 = block1
                self.token = next_block.token
                self.mid = next_block.mid
                self.response_type = None
            else:
                raise iot.error.NotImplemented()
        else:
            raise ValueError("Fatal Error: called appendRequestBlock on non-request message!!!")

    def appendResponseBlock(self, next_block):
        """Append next block to current response message.
           Used when assembling incoming blockwise responses."""
        if self.code.is_response():
            ## @TODO: check etags for consistency
            block2 = next_block.opt.block2
            if block2.block_number * (2 ** (block2.size_exponent + 4)) != len(self.payload):
                raise iot.error.NotImplemented()

            if next_block.opt.etag != self.opt.etag:
                raise iot.error.ResourceChanged()

            self.payload += next_block.payload
            self.opt.block2 = block2
            self.token = next_block.token
            self.mid = next_block.mid
        else:
            raise ValueError("Fatal Error: called appendResponseBlock on non-response message!!!")

    def generateNextBlock2Request(self, response):
        """Generate a request for next response block.
           This method is used by client after receiving
           blockwise response from server with "more" flag set."""
        request = copy.deepcopy(self)
        request.payload = ""
        request.mid = None
        if response.opt.block2.block_number == 0 and response.opt.block2.size_exponent > DEFAULT_BLOCK_SIZE_EXP:
            new_size_exponent = DEFAULT_BLOCK_SIZE_EXP
            new_block_number = 2 ** (response.opt.block2.size_exponent - new_size_exponent)
            request.opt.block2 = (new_block_number, False, new_size_exponent)
        else:
            request.opt.block2 = (response.opt.block2.block_number + 1, False, response.opt.block2.size_exponent)
        request.opt.deleteOption(BLOCK1)
        request.opt.deleteOption(OBSERVE)
        return request

    def generateNextBlock1Response(self):
        """Generate a response to acknowledge incoming request block.
           This method is used by server after receiving
           blockwise request from client with "more" flag set."""
        response = Message(code=CHANGED, token=self.token )
        response.remote = self.remote
        if self.opt.block1.block_number == 0 and self.opt.block1.size_exponent > DEFAULT_BLOCK_SIZE_EXP:
            new_size_exponent = DEFAULT_BLOCK_SIZE_EXP
            response.opt.block1 = (0, True, new_size_exponent)
        else:
            response.opt.block1 = (self.opt.block1.block_number, True, self.opt.block1.size_exponent)
        return response

    def get_request_uri(self):
        """The absolute URI this message belongs to. For requests, this is
        composed from the remote and options (FIXME: or configured proxy data).
        For responses, this is stored by the Requester object not only to
        preserve the request information (which could have been kept by the
        requesting application), but also because the Requester can know about
        multicast responses (which would update the host component) and
        redirects (FIXME do they exist?)."""

        # maybe this function does not belong exactly *here*, but it belongs to
        # the results of .request(message), which is currently a message itself.

        # FIXME this should follow coap section 6.5 more closely

        # FIXME this tries to look up request-specific attributes in responses,
        # maybe it needs completely separate implementations for requests and
        # responses

        proxy_uri = self.opt.getOption(OptionNumber.PROXY_URI)

        if proxy_uri is not None:
            return proxy_uri

        scheme = self.opt.getOption(OptionNumber.PROXY_SCHEME) or 'coap'
        host = self.opt.uri_host or self.remote[0]
        port = self.opt.uri_port or self.remote[1]
        if port == COAP_PORT:
            netloc = host
        else:
            netloc = "%s:%s"%(host, port)

        if self.requested_path is not None:
            path = self.requested_path
        else:
            path = self.opt.uri_path
        path = '/'.join([""] + path) or '/'

        params = "" # are they not there at all?

        if self.requested_query is not None:
            query = self.requested_query
        else:
            query = self.opt.getOption(OptionNumber.URI_QUERY) or ()
        query = "?" + "&".join(query) if query else ""
        fragment = None

        return urllib.parse.urlunparse((scheme, netloc, path, params, query, fragment))


class Options(object):
    """Represent CoAP Header Options."""
    def __init__(self):
        self._options = {}

    def decode(self, rawdata):
        """Decode all options in message from raw binary data."""
        option_number = OptionNumber(0)

        while len(rawdata) > 0:
            if rawdata[0] == 0xFF:
                return rawdata[1:]
            dllen = rawdata[0]
            delta = (dllen & 0xF0) >> 4
            length = (dllen & 0x0F)
            rawdata = rawdata[1:]
            (delta, rawdata) = readExtendedFieldValue(delta, rawdata)
            (length, rawdata) = readExtendedFieldValue(length, rawdata)
            option_number += delta
            option = option_number.create_option(decode=rawdata[:length])
            self.addOption(option)
            rawdata = rawdata[length:]
        return ''

    def encode(self):
        """Encode all options in option header into string of bytes."""
        data = []
        current_opt_num = 0
        option_list = self.optionList()
        for option in option_list:
            delta, extended_delta = writeExtendedFieldValue(option.number - current_opt_num)
            length, extended_length = writeExtendedFieldValue(option.length)
            data.append(bytes([((delta & 0x0F) << 4) + (length & 0x0F)]))
            data.append(extended_delta)
            data.append(extended_length)
            data.append(option.encode())
            current_opt_num = option.number
        return (b''.join(data))

    def addOption(self, option):
        """Add option into option header."""
        self._options.setdefault(option.number, []).append(option)

    def deleteOption(self, number):
        """Delete option from option header."""
        if number in self._options:
            self._options.pop(number)

    def getOption (self, number):
        """Get option with specified number."""
        return self._options.get(number)

    def optionList(self):
        return chain.from_iterable(sorted(self._options.values(), key=lambda x: x[0].number))

    def _setUriPath(self, segments):
        """Convenience setter: Uri-Path option"""
        if isinstance(segments, str): #For Python >3.1 replace with isinstance(segments,str)
            raise ValueError("URI Path should be passed as a list or tuple of segments")
        self.deleteOption(number=OptionNumber.URI_PATH)
        for segment in segments:
            self.addOption(OptionNumber.URI_PATH.create_option(value=str(segment)))

    def _getUriPath(self):
        """Convenience getter: Uri-Path option"""
        segment_list = []
        uri_path = self.getOption(number=OptionNumber.URI_PATH)
        if uri_path is not None:
            for segment in uri_path:
                segment_list.append(segment.value)
        return segment_list

    uri_path = property(_getUriPath, _setUriPath)

    def _setUriQuery(self, segments):
        """Convenience setter: Uri-Query option"""
        if isinstance(segments, str): #For Python >3.1 replace with isinstance(segments,str)
            raise ValueError("URI Query should be passed as a list or tuple of segments")
        self.deleteOption(number=OptionNumber.URI_QUERY)
        for segment in segments:
            self.addOption(OptionNumber.URI_QUERY.create_option(value=str(segment)))

    def _getUriQuery(self):
        """Convenience getter: Uri-Query option"""
        segment_list = []
        uri_query = self.getOption(number=OptionNumber.URI_QUERY)
        if uri_query is not None:
            for segment in uri_query:
                segment_list.append(segment.value)
        return segment_list

    uri_query = property(_getUriQuery, _setUriQuery)

    def _setBlock2(self, block_tuple):
        """Convenience setter: Block2 option"""
        self.deleteOption(number=OptionNumber.BLOCK2)
        self.addOption(BlockOption(number=OptionNumber.BLOCK2, value=block_tuple))

    def _getBlock2(self):
        """Convenience getter: Block2 option"""
        block2 = self.getOption(number=OptionNumber.BLOCK2)
        if block2 is not None:
            return block2[0].value
        else:
            return None

    block2 = property(_getBlock2, _setBlock2)

    def _setBlock1(self, block_tuple):
        """Convenience setter: Block1 option"""
        self.deleteOption(number=OptionNumber.BLOCK1)
        self.addOption(OptionNumber.BLOCK1.create_option(value=block_tuple))

    def _getBlock1(self):
        """Convenience getter: Block1 option"""
        block1 = self.getOption(number=OptionNumber.BLOCK1)
        if block1 is not None:
            return block1[0].value
        else:
            return None

    block1 = property(_getBlock1, _setBlock1)

    def _setContentFormat(self, content_format):
        """Convenience setter: Content-Format option"""
        self.deleteOption(number=OptionNumber.CONTENT_FORMAT)
        self.addOption(OptionNumber.CONTENT_FORMAT.create_option(value=content_format))

    def _getContentFormat(self):
        """Convenience getter: Content-Format option"""
        content_format = self.getOption(number=OptionNumber.CONTENT_FORMAT)
        if content_format is not None:
            return content_format[0].value
        else:
            return None

    content_format = property(_getContentFormat, _setContentFormat)

    def _setETag(self, etag):
        """Convenience setter: ETag option"""
        self.deleteOption(number=OptionNumber.ETAG)
        if etag is not None:
            self.addOption(OptionNumber.ETAG.create_option(value=etag))

    def _getETag(self):
        """Convenience getter: ETag option"""
        etag = self.getOption(number=OptionNumber.ETAG)
        if etag is not None:
            return etag[0].value
        else:
            return None

    etag = property(_getETag, _setETag, None, "Access to a single ETag on the message (as used in responses)")

    def _setETags(self, etags):
        self.deleteOption(number=OptionNumber.ETAG)
        for tag in etags:
            self.addOption(OptionNumber.ETAG.create_option(value=tag))

    def _getETags(self):
        etag = self.getOption(number=OptionNumber.ETAG)
        return [] if etag is None else [tag.value for tag in etag]

    etags = property(_getETags, _setETags, None, "Access to a list of ETags on the message (as used in requests)")

    # FIXME this is largely copy/paste

    def _setObserve(self, observe):
        self.deleteOption(number=OptionNumber.OBSERVE)
        if observe is not None:
            self.addOption(OptionNumber.OBSERVE.create_option(value=observe))

    def _getObserve(self):
        observe = self.getOption(number=OptionNumber.OBSERVE)
        if observe is not None:
            return observe[0].value
        else:
            return None

    observe = property(_getObserve, _setObserve)

    def _setAccept(self, accept):
        self.deleteOption(number=OptionNumber.ACCEPT)
        if accept is not None:
            self.addOption(UintOption(number=OptionNumber.ACCEPT, value=accept))

    def _getAccept(self):
        accept = self.getOption(number=OptionNumber.ACCEPT)
        if accept is not None:
            return accept[0].value
        else:
            return None

    accept = property(_getAccept, _setAccept)

    def _setUriHost(self, uri_host):
        self.deleteOption(number=OptionNumber.URI_HOST)
        if uri_host is not None:
            self.addOption(StringOption(number=OptionNumber.URI_HOST, value=uri_host))

    def _getUriHost(self):
        uri_host = self.getOption(number=OptionNumber.URI_HOST)
        if uri_host is not None:
            return uri_host[0].value
        else:
            return None

    uri_host = property(_getUriHost, _setUriHost)

    def _setUriPort(self, uri_port):
        self.deleteOption(number=OptionNumber.URI_PORT)
        if uri_port is not None:
            self.addOption(IntOption(number=OptionNumber.URI_PORT, value=uri_port))

    def _getUriPort(self):
        uri_port = self.getOption(number=OptionNumber.URI_PORT)
        if uri_port is not None:
            return uri_port[0].value
        else:
            return None

    uri_port = property(_getUriPort, _setUriPort)


def readExtendedFieldValue(value, rawdata):
    """Used to decode large values of option delta and option length
       from raw binary form."""
    if value >= 0 and value < 13:
        return (value, rawdata)
    elif value == 13:
        return (rawdata[0] + 13, rawdata[1:])
    elif value == 14:
        return (struct.unpack('!H', rawdata[:2])[0] + 269, rawdata[2:])
    else:
        raise ValueError("Value out of range.")


def writeExtendedFieldValue(value):
    """Used to encode large values of option delta and option length
       into raw binary form.
       In CoAP option delta and length can be represented by a variable
       number of bytes depending on the value."""
    if value >= 0 and value < 13:
        return (value, b'')
    elif value >= 13 and value < 269:
        return (13, struct.pack('!B', value - 13))
    elif value >= 269 and value < 65804:
        return (14, struct.pack('!H', value - 269))
    else:
        raise ValueError("Value out of range.")


class StringOption(object):
    """String CoAP option - used to represent string options."""

    def __init__(self, number, value=""):
        self.value = value
        self.number = number

    def encode(self):
        # FIXME: actually, this should be utf8 of the net-unicode form (maybe it is)
        rawdata = self.value.encode('utf-8')
        return rawdata

    def decode(self, rawdata):
        self.value = rawdata.decode('utf-8')

    def _length(self):
        return len(self.value)
    length = property(_length)

class OpaqueOption(object):
    """Opaque CoAP option - used to represent opaque options."""

    def __init__(self, number, value=b""):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = self.value
        return rawdata

    def decode(self, rawdata):
        self.value = rawdata  # if rawdata is not None else ""

    def _length(self):
        return len(self.value)
    length = property(_length)


class UintOption(object):
    """Uint CoAP option - used to represent uint options."""

    def __init__(self, number, value=0):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = struct.pack("!L", self.value)  # For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(bytes([0]))

    def decode(self, rawdata):  # For Python >3.1 replace with int.from_bytes()
        value = 0
        for byte in rawdata:
            value = (value * 256) + byte
        self.value = value
        return self

    def _length(self):
        if self.value > 0:
            return (self.value.bit_length() - 1) // 8 + 1
        else:
            return 0
    length = property(_length)


class BlockOption(object):
    """Block CoAP option - special option used only for Block1 and Block2 options.
       Currently it is the only type of CoAP options that has
       internal structure."""
    BlockwiseTuple = collections.namedtuple('BlockwiseTuple', ['block_number', 'more', 'size_exponent'])

    def __init__(self, number, value=(0, None, 0)):
        self.value = self.BlockwiseTuple._make(value)
        self.number = number

    def encode(self):
        as_integer = (self.value[0] << 4) + (self.value[1] * 0x08) + self.value[2]
        rawdata = struct.pack("!L", as_integer)  # For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(bytes([0]))

    def decode(self, rawdata):
        as_integer = 0
        for byte in rawdata:
            as_integer = (as_integer * 256) + byte
        self.value = self.BlockwiseTuple(block_number=(as_integer >> 4), more=bool(as_integer & 0x08), size_exponent=(as_integer & 0x07))

    def _length(self):
        return ((self.value[0].bit_length() + 3) // 8 + 1)
    length = property(_length)

OptionNumber.OBSERVE.format = UintOption
OptionNumber.URI_PORT.format = UintOption
OptionNumber.URI_PATH.format = StringOption
OptionNumber.CONTENT_FORMAT.format = UintOption
OptionNumber.MAX_AGE.format = UintOption
OptionNumber.URI_QUERY.format = StringOption
OptionNumber.ACCEPT.format = UintOption
OptionNumber.BLOCK2.format = BlockOption
OptionNumber.BLOCK1.format = BlockOption
OptionNumber.SIZE2.format = UintOption



def uriPathAsString(segment_list):
    return '/' + '/'.join(segment_list)


class Coap(asyncio.DatagramProtocol):

    def __init__(self, endpoint, loop, loggername="coap"):
        """Initialize a CoAP protocol instance."""
        self.message_id = random.randint(0, 65535)
        self.token = random.randint(0, 65535)
        self.endpoint = endpoint
        self.recent_messages = {}  # recently received messages (identified by message ID and remote)
        self.active_exchanges = {}  # active exchanges i.e. sent CON messages (identified by message ID and remote)
        self.backlogs = {} # per-remote list of backlogged packages (keys exist iff there is an active_exchange with that node)
        self.outgoing_requests = {}  # unfinished outgoing requests (identified by token and remote)
        self.incoming_requests = {}  # unfinished incoming requests (identified by path tuple and remote)
        self.outgoing_observations = {} # observations where this node is the client. (token, remote) -> ClientObservation

        self.log = logging.getLogger(loggername)

        self.loop = loop

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, host_and_port):
        (host, port) = host_and_port
        self.log.debug("received %r from %s:%d" % (data, host, port))
        try:
            message = Message.decode(data, (host, port), self)
        except iot.error.UnparsableMessage:
            logging.warning("Ignoring unparsable message from %s:%d"%(host, port))
            return
        if self.deduplicateMessage(message) is True:
            return
        if message.code.is_request():
            self.processRequest(message)
        elif message.code.is_response():
            self.processResponse(message)
        elif message.code is EMPTY:
            self.processEmpty(message)

    def deduplicateMessage(self, message):
        """Check incoming message if it's a duplicate.

           Duplicate is a message with the same Message ID (mid)
           and sender (remote), as message received within last
           EXCHANGE_LIFETIME seconds (usually 247 seconds)."""

        key = (message.mid, message.remote)
        self.log.debug("Incoming Message ID: %d" % message.mid)
        if key in self.recent_messages:
            if message.mtype is CON:
                if len(self.recent_messages[key]) == 3:
                    self.log.info('Duplicate CON received, sending old response again')
                    self.sendMessage(self.recent_messages[key][2])
                else:
                    self.log.info('Duplicate CON received, no response to send')
            else:
                self.log.info('Duplicate NON, ACK or RST received')
            return True
        else:
            self.log.debug('New unique message received')
            expiration = self.loop.call_later(EXCHANGE_LIFETIME, self.removeMessageFromRecent, key)
            self.recent_messages[key] = (message, expiration)
            return False

    def removeMessageFromRecent(self, key):
        """Remove Message ID+Remote combination from
           recent messages cache."""
        self.recent_messages.pop(key)

    def processResponse(self, response):
        """Method used for incoming response processing."""
        if response.mtype is RST:
            return
        if response.mtype is ACK:
            if response.mid in self.active_exchanges:
                self.removeExchange(response)
            else:
                return
        self.log.debug("Received Response, token: %s, host: %s, port: %s" % (binascii.b2a_hex(response.token), response.remote[0], response.remote[1]))
        if (response.token, response.remote) in self.outgoing_requests:
            self.outgoing_requests.pop((response.token, response.remote)).handleResponse(response)
            if response.mtype is CON:
                #TODO: Some variation of sendEmptyACK should be used
                ack = Message(mtype=ACK, mid=response.mid, code=EMPTY, payload="")
                ack.remote = response.remote
                self.sendMessage(ack)
        elif (response.token, None) in self.outgoing_requests:
            # that's exactly the `MulticastRequester`s so far
            self.outgoing_requests[(response.token, None)].handleResponse(response)
        elif (response.token, response.remote) in self.outgoing_observations:
            ## @TODO: deduplication based on observe option value, collecting
            # the rest of the resource if blockwise
            self.outgoing_observations[(response.token, response.remote)].callback(response)

            if response.mtype is CON:
                #TODO: Some variation of sendEmptyACK should be used (as above)
                ack = Message(mtype=ACK, mid=response.mid, code=EMPTY, payload="")
                ack.remote = response.remote
                self.sendMessage(ack)

            if response.opt.observe is None:
                self.outgoing_observations[(response.token, response.remote)].error(iot.error.ObservationCancelled())
        else:
            self.log.info("Response not recognized - sending RST.")
            rst = Message(mtype=RST, mid=response.mid, code=EMPTY, payload='')
            rst.remote = response.remote
            self.sendMessage(rst)

    def processRequest(self, request):
        """Method used for incoming request processing."""
        if request.mtype not in (CON, NON):
            response = Message(code=BAD_REQUEST, payload='Wrong message type for request!')
            self.respond(response, request)
            return
        if (tuple(request.opt.uri_path), request.remote) in self.incoming_requests:
            self.log.debug("Request pertains to earlier blockwise requests.")
            self.incoming_requests.pop((tuple(request.opt.uri_path), request.remote)).handleNextRequest(request)
        else:
            responder = Responder(self, request)

    def processEmpty(self, message):
        if message.mtype is CON:
            self.log.info('Empty CON message received (CoAP Ping) - replying with RST.')
            rst = Message(mtype=RST, mid=message.mid, code=EMPTY, payload='')
            rst.remote = message.remote
            self.sendMessage(rst)
        #TODO: passing ACK/RESET info to application
        #Currently it doesn't matter if empty ACK or RST is received - in both cases exchange has to be removed
        if message.mid in self.active_exchanges and message.mtype in (ACK, RST):
            self.removeExchange(message)

    def sendMessage(self, message):
        """Set Message ID, encode and send message.
           Also if message is Confirmable (CON) add Exchange"""
        host, port = message.remote

        if message.mtype == CON and is_multicast_remote(message.remote):
            raise ValueError("Refusing to send CON message to multicast address")

        self.log.debug("Sending message to %s:%d" % (host, port))
        recent_key = (message.mid, message.remote)
        if recent_key in self.recent_messages:
            if len(self.recent_messages[recent_key]) != 3:
                self.recent_messages[recent_key] = self.recent_messages[recent_key] + (message,)

        if message.mid is None:
            message.mid = self.nextMessageID()

        self.enqueueForSending(message)

    def enqueueForSending(self, message):
        if message.remote in self.backlogs:
            self.log.debug("Message to %s put into backlog"%(message.remote,))
            self.backlogs[message.remote].append(message)
        else:
            self.send(message)

    def send(self, message):
        if message.mtype is CON:
            self.addExchange(message)
        msg = message.encode()
        self.transport.sendto(msg, message.remote)
        self.log.debug("Message %r sent successfully" % msg)

    def nextMessageID(self):
        """Reserve and return a new message ID."""
        message_id = self.message_id
        self.message_id = 0xFFFF & (1 + self.message_id)
        return message_id

    def nextToken(self):
        """Reserve and return a new Token for request."""
        #TODO: add proper Token handling
        token = self.token
        self.token = (self.token + 1) & 0xffffffffffffffff
        return binascii.a2b_hex("%08x"%self.token)

    def addExchange(self, message):
        """Add an "exchange" for outgoing CON message.

           CON (Confirmable) messages are automatically
           retransmitted by protocol until ACK or RST message
           with the same Message ID is received from target host."""

        self.backlogs.setdefault(message.remote, [])

        timeout = random.uniform(ACK_TIMEOUT, ACK_TIMEOUT * ACK_RANDOM_FACTOR)
        retransmission_counter = 0
        next_retransmission = self.loop.call_later(timeout, self.retransmit, message, timeout, retransmission_counter)
        self.active_exchanges[message.mid] = (message, next_retransmission)
        self.log.debug("Exchange added, Message ID: %d." % message.mid)

    def removeExchange(self, message):
        """Remove exchange from active exchanges and cancel the timeout
           to next retransmission."""
        self.active_exchanges.pop(message.mid)[1].cancel()
        self.log.debug("Exchange removed, Message ID: %d." % message.mid)

        if message.remote not in self.backlogs:
            # if active exchanges were something we could do a
            # .register_finally() on, we could chain them like that; if we
            # implemented anything but NSTART=1, we'll need a more elaborate
            # system anyway
            raise AssertionError("backlogs/active_exchange relation violated (implementation error)")

        while not any(m.remote == message.remote for m, t in self.active_exchanges.values()):
            if self.backlogs[message.remote] != []:
                next_message = self.backlogs[message.remote].pop(0)
                self.send(next_message)
            else:
                del self.backlogs[message.remote]
                break

    def retransmit(self, message, timeout, retransmission_counter):
        """Retransmit CON message that has not been ACKed or RSTed."""
        self.active_exchanges.pop(message.mid)
        if retransmission_counter < MAX_RETRANSMIT:
            self.transport.sendto(message.encode(), message.remote)
            retransmission_counter += 1
            timeout *= 2
            next_retransmission = self.loop.call_later(timeout, self.retransmit, message, timeout, retransmission_counter)
            self.active_exchanges[message.mid] = (message, next_retransmission)
            self.log.info("Retransmission, Message ID: %d." % message.mid)
        else:
            pass
            #TODO: error handling (especially for requests)

    def request(self, request, observeCallback=None, block1Callback=None, block2Callback=None,
                observeCallbackArgs=None, block1CallbackArgs=None, block2CallbackArgs=None,
                observeCallbackKeywords=None, block1CallbackKeywords=None, block2CallbackKeywords=None):
        """Send a request.

           This is a method that should be called by user app."""
        return Requester(self, request, observeCallback, block1Callback, block2Callback,
                         observeCallbackArgs, block1CallbackArgs, block2CallbackArgs,
                         observeCallbackKeywords, block1CallbackKeywords, block2CallbackKeywords).response

    def multicast_request(self, request):
        return MulticastRequester(self, request).responses


class Requester(object):
    """Class used to handle single outgoing request.

       Class includes methods that handle sending
       outgoing blockwise requests and receiving incoming
       blockwise responses."""

    def __init__(self, protocol, app_request, observeCallback, block1Callback, block2Callback,
                       observeCallbackArgs, block1CallbackArgs, block2CallbackArgs,
                       observeCallbackKeywords, block1CallbackKeywords, block2CallbackKeywords):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.app_request = app_request
        self.assembled_response = None
        assert observeCallback == None or callable(observeCallback)
        assert block1Callback == None or callable(block1Callback)
        assert block2Callback == None or callable(block2Callback)
        self.cbs = ((block1Callback, block1CallbackArgs, block1CallbackKeywords),
                    (block2Callback, block2CallbackArgs, block2CallbackKeywords))
        if app_request.opt.observe is not None:
            self.observation = ClientObservation(app_request)
            if observeCallback is not None:
                self.observation.register_callback(lambda result, cb=observeCallback, args=observeCallbackArgs or (), kwargs=observeCallbackKeywords or {}: cb(result, *args, **kwargs))
        if self.app_request.code.is_request() is False:
            raise ValueError("Message code is not valid for request")
        size_exp = DEFAULT_BLOCK_SIZE_EXP
        if len(self.app_request.payload) > (2 ** (size_exp + 4)):
            raise Exception("multiblock handling broken, length %s"%len(self.app_request.payload))
            request = self.app_request.extractBlock(0, size_exp)
            self.app_request.opt.block1 = request.opt.block1
        else:
            request = self.app_request

        self.response = self.sendRequest(request)
        # ASYNCIO FIXME chained deferreds
        #self.deferred.add_done_callback(self.processBlock1InResponse)
        #self.deferred.add_done_callback(self.processBlock2InResponse)

    def sendRequest(self, request):
        """Send a request or single request block.

           This method is used in 3 situations:
           - sending non-blockwise request
           - sending blockwise (Block1) request block
           - asking server to send blockwise (Block2) response block
        """

        def cancelRequest(d):
            """Clean request after cancellation from user application."""

            if d.cancelled():
                self.log.debug("Request cancelled")
                # actually, it might be a good idea to always do this here and nowhere else
                self.protocol.outgoing_requests.pop((request.token, request.remote))

        def timeoutRequest(d):
            """Clean the Request after a timeout."""

            self.log.info("Request timed out")
            del self.protocol.outgoing_requests[(request.token, request.remote)]
            d.errback(iot.error.RequestTimedOut())

        def gotResult(result):
            timeout.cancel()

        if request.mtype is None:
            request.mtype = CON
        request.token = self.protocol.nextToken()
        try:
            self.protocol.sendMessage(request)
        except Exception as e:
            f = asyncio.Future()
            f.set_exception(e)
            return f
        else:
            d = asyncio.Future()
            d.add_done_callback(cancelRequest)
            timeout = self.protocol.loop.call_later(REQUEST_TIMEOUT, timeoutRequest, d)
            d.add_done_callback(gotResult)
            self.protocol.outgoing_requests[(request.token, request.remote)] = self
            self.log.debug("Sending request - Token: %s, Host: %s, Port: %s" % (binascii.b2a_hex(request.token), request.remote[0], request.remote[1]))
            if hasattr(self, 'observation'):
                d.add_done_callback(self.registerObservation)
            return d

    def handleResponse(self, response):
        response.requested_path = self.app_request.opt.uri_path
        response.requested_query = self.app_request.opt.getOption(OptionNumber.URI_QUERY) or ()

        d, self.response = self.response, None
        d.set_result(response)

    def registerObservation(self, response_future):
        try:
            response = response_future.result()
        except Exception as e:
            observation.error(e)
            return

        if response.opt.observe is None:
            self.observation.error(iot.error.NotObservable())
        else:
            self.observation._register(self.protocol.outgoing_observations, (response.token, response.remote))

    def processBlock1InResponse(self, response_future):
        """Process incoming response with regard to Block1 option.

           Method is called for all responses, with or without Block1
           option.

           Method is recursive - calls itself until all request blocks
           are sent."""

        raise NotImplementedError("Not ported to asyncio yet")

        if response.opt.block1 is not None:
            block1 = response.opt.block1
            self.log.debug("Response with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))
            if block1.block_number == self.app_request.opt.block1.block_number:
                if block1.size_exponent < self.app_request.opt.block1.size_exponent:
                    next_number = (self.app_request.opt.block1.block_number + 1) * 2 ** (self.app_request.opt.block1.size_exponent - block1.size_exponent)
                    next_block = self.app_request.extractBlock(next_number, block1.size_exponent)
                else:
                    next_block = self.app_request.extractBlock(self.app_request.opt.block1.block_number + 1, block1.size_exponent)
                if next_block is not None:
                    self.app_request.opt.block1 = next_block.opt.block1
                    block1Callback, args, kw = self.cbs[0]
                    if block1Callback is None:
                        return self.sendNextRequestBlock(None, next_block)
                    else:
                        args = args or ()
                        kw = kw or {}
                        d = block1Callback(response, *args, **kw)
                        d.addCallback(self.sendNextRequestBlock, next_block)
                        return d
                else:
                    if block1.more is False:
                        return defer.succeed(response)
                    else:
                        return defer.fail()
            else:
                return defer.fail()
        else:
            if self.app_request.opt.block1 is None:
                return defer.succeed(response)
            else:
                return defer.fail()

    def sendNextRequestBlock(self, result, next_block):
        """Helper method used for sending request blocks."""
        self.log.debug("Sending next block of blockwise request.")
        self.deferred = self.sendRequest(next_block)
        self.deferred.add_done_callback(self.processBlock1InResponse)
        return self.deferred

    def processBlock2InResponse(self, response_future):
        """Process incoming response with regard to Block2 option.

           Method is called for all responses, with or without Block2
           option.

           Method is recursive - calls itself until all response blocks
           from server are received."""

        response = response_future.result()

        if response.opt.block2 is not None:
            block2 = response.opt.block2
            self.log.debug("Response with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            if self.assembled_response is not None:
                try:
                    self.assembled_response.appendResponseBlock(response)
                except iot.error.Error as e:
                    return defer.fail(e)
            else:
                if block2.block_number is 0:
                    self.log.debug("Receiving blockwise response")
                    self.assembled_response = response
                else:
                    self.log.warning("ProcessBlock2 error: transfer started with nonzero block number.")
                    return defer.fail()
            if block2.more is True:
                request = self.app_request.generateNextBlock2Request(response)
                block2Callback, args, kw = self.cbs[1]
                # ASYNCIO FIXME deferred return
                if block2Callback is None:
                    return self.askForNextResponseBlock(None, request)
                else:
                    args = args or ()
                    kw = kw or {}
                    d = block2Callback(response, *args, **kw)
                    d.addCallback(self.askForNextResponseBlock, request)
                    return d
            else:
                return defer.succeed(self.assembled_response)
        else:
            if self.assembled_response is None:
                return defer.succeed(response)
            else:
                return defer.fail(iot.error.MissingBlock2Option)

    def askForNextResponseBlock(self, result, request):
        """Helper method used to ask server to send next response block."""
        self.log.debug("Requesting next block of blockwise response.")
        self.deferred = self.sendRequest(request)
        self.deferred.addCallback(self.processBlock2InResponse)
        return self.deferred

class MulticastRequester(object):
    def __init__(self, protocol, request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.request = request

        if self.request.mtype != NON or self.request.code != GET or self.request.payload:
            raise ValueError("Multicast currently only supportet for NON GET")

        self.responses = QueueWithEnd()
        self.sendRequest(request)

    def sendRequest(self, request):
        request.token = self.protocol.nextToken()

        try:
            self.protocol.sendMessage(request)
        except Exception as e:
            self.responses.set_exception(e)
            return

        self.protocol.outgoing_requests[(request.token, None)] = self
        self.log.debug("Sending multicast request - Token: %s, Remote: %s" % (binascii.b2a_hex(request.token), request.remote))

        self.protocol.loop.call_later(MULTICAST_REQUEST_TIMEOUT, self._timeout)

    def handleResponse(self, response):
        response.requested_path = self.request.opt.uri_path
        response.requested_query = self.request.opt.getOption(OptionNumber.URI_QUERY) or ()

        # FIXME this should somehow backblock, but it's udp
        asyncio.async(self.responses.put(response))

    def _timeout(self):
        self.protocol.outgoing_requests.pop(self.request.token, None)
        self.responses.finish()

class Responder(object):
    """Class used to handle single incoming request.

       Class includes methods that handle receiving
       incoming blockwise requests, searching for target
       resources, preparing responses and sending outgoing
       blockwise responses.
       """

    def __init__(self, protocol, request):
        self.protocol = protocol
        self.log = self.protocol.log.getChild("requester")
        self.assembled_request = None
        self.app_response = None
        self.log.debug("Request doesn't pertain to earlier blockwise requests.")
        self.all_blocks_arrived = asyncio.Future()

        asyncio.Task(self.dispatchRequest(self.all_blocks_arrived))

        self.processBlock1InRequest(request)

    def processBlock1InRequest(self, request):
        """Process incoming request with regard to Block1 option.

           Method is recursive - calls itself until all request blocks
           are received."""
        if request.opt.block1 is not None:
            block1 = request.opt.block1
            self.log.debug("Request with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))
            if block1.block_number == 0:
                #TODO: Check if resource is available - if not send error immediately
                #TODO: Check if method is allowed - if not send error immediately
                self.log.debug("New or restarted incoming blockwise request.")
                self.assembled_request = request
            else:
                try:
                    self.assembled_request.appendRequestBlock(request)
                except (iot.error.NotImplemented, AttributeError):
                    self.respondWithError(request, NOT_IMPLEMENTED, "Error: Request block received out of order!")
                    return defer.fail(iot.error.NotImplemented())
                    #raise iot.error.NotImplemented
            if block1.more is True:
                #TODO: SUCCES_CODE Code should be either Changed or Created - Resource check needed
                #TODO: SIZE_CHECK1 should check if the size of incoming payload is still acceptable
                #TODO: SIZE_CHECK2 should check if Size option is present, and reject the resource if size too large
                return self.acknowledgeRequestBlock(request)
            else:
                self.log.debug("Complete blockwise request received.")
                return defer.succeed(self.assembled_request)
        else:
            if self.assembled_request is not None:
                self.log.warning("Non-blockwise request received during blockwise transfer. Blockwise transfer cancelled.")
            self.all_blocks_arrived.set_result(request)

    def acknowledgeRequestBlock(self, request):
        """Helper method used to ask client to send next request block."""
        self.log.debug("Sending block acknowledgement (allowing client to send next block).")
        response = request.generateNextBlock1Response()
        self.deferred = self.sendNonFinalResponse(response, request)
        self.deferred.add_done_callback(self.processBlock1InRequest)
        return self.deferred

    def dispatchRequest(self, request):
        """Dispatch incoming request - search endpoint
           resource tree for resource in Uri Path
           and call proper CoAP Method on it."""
    @asyncio.coroutine
    def dispatchRequest(self, request_future):
        """Dispatch incoming request - search endpoint
           resource tree for resource in Uri Path
           and call proper CoAP Method on it."""

        try:
            request = yield from request_future
        except iot.NotImplementedError as e:
            """Handle (silently ignore) request errors related
               to Block1. Currently it's used only to ignore
               requests which are send non-sequentially"""
            self.log.error("Block1 assembly on request failed: %r", e)
            return

        #TODO: Request with Block2 option and non-zero block number should get error response
        request.prepath = []
        request.postpath = request.opt.uri_path
        try:
            resource = self.protocol.endpoint.getResourceFor(request)
            unfinished_response = resource.render(request)
        except iot.error.NoResource:
            self.respondWithError(request, NOT_FOUND, "Error: Resource not found!")
        except iot.error.UnallowedMethod:
            self.respondWithError(request, METHOD_NOT_ALLOWED, "Error: Method not allowed!")
        except iot.error.UnsupportedMethod:
            self.respondWithError(request, METHOD_NOT_ALLOWED, "Error: Method not recognized!")
        else:
            delayed_ack = self.protocol.loop.call_later(EMPTY_ACK_DELAY, self.sendEmptyAck, request)

            try:
                response = yield from unfinished_response
            except Exception as e:
                self.log.error("An exception occurred while rendering a resource: %r"%e)
                response = Message(code=iot.coap.INTERNAL_SERVER_ERROR)

            if resource.observable and request.code == GET and request.opt.observe is not None:
                self.handleObserve(response, request, resource)

            self.respond(response, request, delayed_ack)

    def respondWithError(self, request, code, payload):
        """Helper method to send error response to client."""
        payload = payload.encode('ascii')
        self.log.info("Sending error response: %r"%payload)
        response = Message(code=code, payload=payload)
        self.respond(response, request)
        return

    def handleObserve(self, app_response, request, resource):
        """Intermediate state of sending a response that the response will go
        through if it might need to be processed for observation. This both
        handles the implications for notification sending and adds the observe
        response option."""

        observation_identifier = (request.remote, request.token)

        if app_response.code not in (VALID, CONTENT):
            if observation_identifier in resource.observers:
                ## @TODO cancel observation
                pass

        if observation_identifier in resource.observers:
            pass ## @TODO renew that observation (but keep in mind that whenever we send a notification, the original message is replayed)
        else:
            obs = ServerObservation(request)
            resource.observers[observation_identifier] = obs

        app_response.opt.observe = resource.observe_index


    def respond(self, app_response, request, delayed_ack=None):
        """Take application-supplied response and prepare it
           for sending."""

        self.log.debug("Preparing response...")
        if delayed_ack is not None:
            delayed_ack.cancel()
        self.app_response = app_response
        size_exp = min(request.opt.block2.size_exponent if request.opt.block2 is not None else DEFAULT_BLOCK_SIZE_EXP, DEFAULT_BLOCK_SIZE_EXP)
        if len(self.app_response.payload) > (2 ** (size_exp + 4)):
            response = self.app_response.extractBlock(0, size_exp)
            self.app_response.opt.block2 = response.opt.block2
            self.sendResponseBlock(response, request)
        else:
            self.sendResponse(app_response, request)

    def processBlock2InRequest(self, request_future):
        """Process incoming request with regard to Block2 option.

           Method is recursive - calls itself until all response blocks
           are sent to client."""

        request = request_future.result()

        if request.opt.block2 is not None:
            block2 = request.opt.block2
            self.log.debug("Request with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            sent_length = (2 ** (self.app_response.opt.block2.size_exponent + 4)) * (self.app_response.opt.block2.block_number + 1)
            #TODO: compare block size of request and response - calculate new block_number if necessary
            if (2 ** (block2.size_exponent + 4)) * block2.block_number == sent_length:
                next_block = self.app_response.extractBlock(block2.block_number, block2.size_exponent)
                if next_block is None:
                    self.log.warning("Block out of range")
                    # ASYNCIO FIXME deferred return
                    return defer.fail()
                if next_block.opt.block2.more is True:
                    self.app_response.opt.block2 = next_block.opt.block2
                    return self.sendResponseBlock(next_block, request)
                else:
                    self.sendResponse(next_block, request)
                    return defer.succeed(None)
            else:
                self.log.warning("Incorrect block number requested")
                return defer.fail()
        else:
            return defer.fail()

    def sendResponseBlock(self, response_block, request):
        """Helper method to send next response block to client."""
        self.log.debug("Sending response block.")
        self.deferred = self.sendNonFinalResponse(response_block, request)
        self.deferred.add_done_callback(self.processBlock2InRequest)
        return self.deferred

    def sendNonFinalResponse(self, response, request):
        """Helper method to send, a response to client, and setup
           a timeout for client."""

        def cancelNonFinalResponse(d):
            if d.cancelled():
                self.log.debug("Waiting for next client request cancelled")
                self.protocol.incoming_requests.pop((tuple(request.opt.uri_path), request.remote))

        def timeoutNonFinalResponse(d):
            """Clean the Response after a timeout."""

            self.log.info("Waiting for next blockwise request timed out")
            self.protocol.incoming_requests.pop((tuple(request.opt.uri_path), request.remote))
            d.set_exception(iot.error.WaitingForClientTimedOut())

        def gotResult(result):
            timeout.cancel()

        d = asyncio.Future()
        d.add_done_callback(cancelNonFinalResponse)
        timeout = self.protocol.loop.call_later(MAX_TRANSMIT_WAIT, timeoutNonFinalResponse, d)
        d.add_done_callback(gotResult)
        self.protocol.incoming_requests[(tuple(request.opt.uri_path), request.remote)] = self
        self.sendResponse(response, request)
        return d

    def handleNextRequest(self, request):
        d, self.deferred = self.deferred, None
        d.callback(request)

    def sendResponse(self, response, request):
        """Send a response or single response block.

           This method is used in 4 situations:
           - sending success non-blockwise response
           - asking client to send blockwise (Block1) request block
           - sending blockwise (Block2) response block
           - sending any error response
        """
        #if response.code.is_response() is False:
            #raise ValueError("Message code is not valid for a response.")
        response.token = request.token
        self.log.debug("Sending token: %s" % (response.token))
        response.remote = request.remote
        if request.opt.block1 is not None:
            response.opt.block1 = request.opt.block1
        if response.mtype is None:
            if request.response_type is None:
                if request.mtype is CON:
                    response.mtype = ACK
                else:
                    response.mtype = NON
            elif request.response_type is ACK:
                response.mtype = CON
            else:
                raise Exception()
        request.response_type = response.mtype
        if response.mid is None:
            if response.mtype in (ACK, RST):
                response.mid = request.mid
        self.log.debug("Sending response, type = %s (request type = %s)" % (response.mtype.name, request.mtype.name))
        self.protocol.sendMessage(response)

    def sendEmptyAck(self, request):
        """Send separate empty ACK when response preparation takes too long."""
        self.log.debug("Response preparation takes too long - sending empty ACK.")
        ack = Message(mtype=ACK, code=EMPTY, payload="")
        self.respond(ack, request)

class ServerObservation(object):
    """An active CoAP observation inside a server is described as a
    ServerObservation object attached to a Resource in .observers[(address,
    token)].

    It keeps a complete copy of the original request for simplicity (while it
    actually would only need parts of that request, like the accept option)."""

    def __init__(self, original_request):
        self.original_request = original_request

    def trigger(self):
        # bypassing parsing and duplicate detection, pretend the request came in again
        print("triggering retransmission with original request %r (will set response_type to ACK)"%vars(self.original_request))
        self.original_request.response_type = ACK # trick responder into sending CON
        Responder(self.original_request.protocol, self.original_request)
        ## @TODO pass a callback down to the exchange -- if it gets a RST, we have to unregister

class ClientObservation(object):
    def __init__(self, original_request):
        self.original_request = original_request
        self.callbacks = []
        self.errbacks = []

        self._registry_data = None

    def register_callback(self, callback):
        """Call the callback whenever a response to the message comes in, and
        pass the response to it."""
        self.callbacks.append(callback)

    def register_errback(self, callback):
        """Call the callback whenever something goes wrong with the
        observation, and pass an exception to the callback. After such a
        callback is called, no more callbacks will be issued."""
        self.errbacks.append(callback)

    def callback(self, response):
        """Notify all listeners of an incoming response"""

        for c in self.callbacks:
            c(response)

    def error(self, exception):
        """Notify registered listeners that the observation went wrong. This
        can only be called once."""

        for c in self.errbacks:
            c(exception)

        self.cancel()

    def cancel(self):
        """Cease to generate observation or error events. This will not
        generate an error by itself."""

        # make sure things go wrong when someone tries to continue this
        self.errbacks = None
        self.callbacks = None

        self._unregister()

    def _register(self, observation_dict, key):
        """Insert the observation into a dict (observation_dict) at the given
        key, and store those details for use during cancellation."""

        if key in observation_dict:
            raise ValueError("Observation conflicts with a registered observation.")

        if self._registry_data is not None:
            raise ValueError("Already registered.")

        self._registry_data = (observation_dict, key)

        observation_dict[key] = self

    def _unregister(self):
        """Undo the registration done in _register if it was ever done."""

        if self._registry_data is not None:
            del self._registry_data[0][self._registry_data[1]]
