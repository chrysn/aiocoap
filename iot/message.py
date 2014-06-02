import urllib
import struct
import copy

from .numbers import *
from .options import Options

class Message(object):
    """A CoAP Message."""

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
        path = '/'.join(("",) + path) or '/'

        params = "" # are they not there at all?

        if self.requested_query is not None:
            query = self.requested_query
        else:
            query = self.opt.getOption(OptionNumber.URI_QUERY) or ()
        query = "?" + "&".join(query) if query else ""
        fragment = None

        return urllib.parse.urlunparse((scheme, netloc, path, params, query, fragment))
