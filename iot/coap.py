'''
Created on 08-09-2012

@author: Maciej Wasilak
'''
import random
import copy
import struct
import collections
from itertools import chain

from twisted.internet import protocol, defer, reactor
from twisted.python import log, failure
import iot.error


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

ACK_TIMEOUT  = 2.0
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

DEFAULT_BLOCK_SIZE_EXP = 2 #Block size 64
"""Default size exponent for blockwise transfers."""


EMPTY_ACK_DELAY = 0.1
"""After this time protocol sends empty ACK, and separate response"""


CON = 0
"""Confirmable message type."""
    
NON = 1
"""Non-confirmable message type."""

ACK = 2
"""Acknowledgement message type."""

RST = 3
"""Reset message type"""

types = { 0: 'CON',
          1: 'NON',
          2: 'ACK',
          3: 'RST'}


EMPTY = 0
GET = 1
POST = 2
PUT = 3
DELETE = 4
CREATED = 65
DELETED = 66
VALID   = 67
CHANGED = 68
CONTENT = 69
BAD_REQUEST              = 128
UNAUTHORIZED             = 129
BAD_OPTION               = 130
FORBIDDEN                = 131
NOT_FOUND                = 132
METHOD_NOT_ALLOWED       = 133
NOT_ACCEPTABLE           = 134
PRECONDITION_FAILED      = 140
REQUEST_ENTITY_TOO_LARGE = 141
UNSUPPORTED_MEDIA_TYPE   = 143
INTERNAL_SERVER_ERROR  = 160
NOT_IMPLEMENTED        = 161
BAD_GATEWAY            = 162
SERVICE_UNAVAILABLE    = 163
GATEWAY_TIMEOUT        = 164
PROXYING_NOT_SUPPORTED = 165

requests = { 1: 'GET',
             2: 'POST',
             3: 'PUT',
             4: 'DELETE'}

responses = { 65: '2.01 Created',
              66: '2.02 Deleted',
              67: '2.03 Valid',
              68: '2.04 Changed',
              69: '2.05 Content',
              128: '4.00 Bad Request',
              129: '4.01 Unauthorized',
              130: '4.02 Bad Option',
              131: '4.03 Forbidden',
              132: '4.04 Not Found',
              133: '4.05 Method Not Allowed',
              134: '4.06 Not Acceptable',
              136: '4.08 Request Entity Incomplete',
              140: '4.12 Precondition Failed',
              141: '4.13 Request Entity Too Large',
              143: '4.15 Unsupported Media Type',
              160: '5.00 Internal Server Error',
              161: '5.01 Not Implemented',
              162: '5.02 Bad Gateway',
              163: '5.03 Service Unavailable',
              164: '5.04 Gateway Timeout',
              165: '5.05 Proxying Not Supported' }

#============================================================================
# coap-13, block-09, observe-06
#============================================================================
# +-----+---+---+---+---+----------------+--------+--------+-------------+
# | No. | C | U | N | R | Name           | Format | Length | Default     |
# +-----+---+---+---+---+----------------+--------+--------+-------------+
# |   1 | x |   |   | x | If-Match       | opaque | 0-8    | (none)      |
# |   3 | x | x |   |   | Uri-Host       | string | 1-255  | (see below) |
# |   4 |   |   |   | x | ETag           | opaque | 1-8    | (none)      |
# |   5 | x |   |   |   | If-None-Match  | empty  | 0      | (none)      |
# |   6 | ? | ? | ? | ? | Observe        | uint   | ?      | (none)      |
# |   7 | x | x |   |   | Uri-Port       | uint   | 0-2    | (see below) |
# |   8 |   |   |   | x | Location-Path  | string | 0-255  | (none)      |
# |  11 | x | x |   | x | Uri-Path       | string | 0-255  | (none)      |
# |  12 |   |   |   |   | Content-Format | uint   | 0-2    | (none)      |
# |  14 |   | x |   |   | Max-Age        | uint   | 0-4    | 60          |
# |  15 | x | x |   | x | Uri-Query      | string | 1-255  | (none)      |
# |  16 |   |   |   | x | Accept         | uint   | 0-2    | (none)      |
# |  20 |   |   |   | x | Location-Query | string | 0-255  | (none)      |
# |  23 | x | ? | ? | ? | Block2         | uint   | 1-3    | (see below) |
# |  27 | x | ? | ? | ? | Block1         | uint   | 1-3    | (see below) |
# |  28 |   | ? | ? | ? | Size           | uint   | 0-4    | (none)      |
# |  35 | x | x |   |   | Proxy-Uri      | string | 1-1034 | (none)      |
# +-----+---+---+---+---+----------------+--------+--------+-------------+
#============================================================================

IF_MATCH       =  1
URI_HOST       =  3
ETAG           =  4
IF_NONE_MATCH  =  5
OBSERVE        =  6
URI_PORT       =  7
LOCATION_PATH  =  8
URI_PATH       = 11
CONTENT_FORMAT = 12
MAX_AGE        = 14
URI_QUERY      = 15
ACCEPT         = 16
LOCATION_QUERY = 20
BLOCK2         = 23
BLOCK1         = 27
SIZE           = 28
PROXY_URI      = 35 


OPTIONS = {'If-Match'       : 1,
           'Uri-Host'       : 3,
           'ETag'           : 4,
           'If-None-Match'  : 5,
           'Observe'        : 6,
           'Uri-Port'       : 7,
           'Location-Path'  : 8,
           'Uri-Path'       : 11,
           'Content-Format' : 12,
           'Max-Age'        : 14,
           'Uri-Query'      : 15,
           'Accept'         : 16,
           'Location-Query' : 20,
           'Block2'         : 23,
           'Block1'         : 27,
           'Size'           : 28,
           'Proxy-Uri'      : 35} 

media_types = { 0: 'text/plain',
                40: 'application/link-format',
                41: 'application/xml',
                42: 'application/octet-stream',
                47: 'application/exi',
                50: 'application/json' }
"""A map from CoAP-assigned integral codes to Internet media type descriptions."""






class Message (object):
    """A CoAP Message."""
   
    def __init__(self, mtype=None, mid=None, code=EMPTY, payload='', token=''):
        self.version = 1
        self.mtype = mtype
        self.mid = mid
        self.code = code
        self.token = token
        self.payload = payload
        self.opt = Options()
        
        self.response_type = None
        self.remote = None
        self.prepath = None
        self.postpath = None
        
        if self.payload is None:
            raise TypeError("Payload must not be None. Use empty string instead.")
 
    @classmethod
    def decode(cls, rawdata, remote = None, protocol = None):
        """Create Message object from binary representation of message."""
        (vttkl, code, mid) = struct.unpack('!BBH', rawdata[:4])
        version = (vttkl & 0xC0) >> 6
        if version is not 1:
            raise Exception()
        mtype = (vttkl & 0x30) >> 4
        token_length = (vttkl & 0x0F)
        msg = Message(mtype=mtype, mid=mid,  code=code)
        msg.token = rawdata[4:4+token_length]
        msg.payload = msg.opt.decode(rawdata[4+token_length:])
        msg.remote = remote
        msg.protocol = protocol
        return msg
       
    def encode(self):
        """Create binary representation of message from Message object."""
        rawdata = chr((self.version << 6) + ((self.mtype & 0x03) << 4) + (len(self.token) & 0x0F))
        rawdata += struct.pack('!BH', self.code, self.mid)
        rawdata += self.token
        rawdata += self.opt.encode()
        if len(self.payload) > 0:
            rawdata += chr(0xFF)
            rawdata += self.payload
        return rawdata

    def extractBlock(self, number, size_exp):
        """Extract block from current message."""
        size = 2**(size_exp+4)
        start = number * size
        if start < len(self.payload):
            end = start + size if start + size < len(self.payload) else len(self.payload)
            block = copy.deepcopy(self)
            block.payload = block.payload[start:end]
            block.mid = None
            more = True if end < len(self.payload) else False
            if isRequest(block.code):
                block.opt.block1 = (number, more, size_exp)
            else:
                block.opt.block2 = (number, more, size_exp)
            return block
    
    def generateNextBlock2Request(self, response):
        """Generate a request for next response block.
           This method is used by client after receiving 
           blockwise response from server with "more" flag set."""
        request = copy.deepcopy(self)
        request.payload = ""
        request.mid = None
        request.opt.block2 = (response.opt.block2.block_number+1, False, response.opt.block2.size_exponent)
        return request
    
    def generateNextBlock1Response(self):
        """Generate a response to acknowledge incoming request block.
           This method is used by server after receiving 
           blockwise request from client with "more" flag set."""
        response = Message(code = CHANGED, token=self.token )
        response.remote=self.remote
        response.opt.block1 = (self.opt.block1.block_number, True, self.opt.block1.size_exponent)
        return response
      

   
class Options(object):
    """Represent CoAP Header Options."""   
    def __init__(self):
        self._options = {}
   
    def decode(self,rawdata):
        option_number = 0
       
        while len(rawdata) > 0:
            if ord(rawdata[0]) is 0xFF:
                return rawdata[1:]
            dllen = ord(rawdata[0])
            delta = (dllen & 0xF0) >> 4
            length = (dllen & 0x0F)
            rawdata = rawdata[1:]
            (delta, rawdata) = readExtendedFieldValue(delta, rawdata)
            (length, rawdata) = readExtendedFieldValue(length, rawdata)
            option_number += delta
            option = option_formats.get(option_number, StringOption)(option_number)
            option.decode(rawdata[:length])    
            self.addOption(option)
            rawdata = rawdata[length:]
        return ''

    def encode(self):
        data = []
        current_opt_num = 0
        option_list = chain.from_iterable(sorted(self._options.values(), key=lambda x: x[0].number))
        for option in option_list:
            delta, extended_delta = writeExtendedFieldValue(option.number - current_opt_num)
            length, extended_length = writeExtendedFieldValue(option.length) 
            data.append( chr(((delta & 0x0F) << 4) + (length & 0x0F)) )
            data.append(extended_delta)
            data.append(extended_length)
            data.append(option.encode())
            current_opt_num = option.number
        return (''.join(data))
   
    def addOption(self, option):
        self._options.setdefault(option.number,[]).append(option)    
    
    def deleteOption(self, number):
        if number in self._options:
            self._options.pop(number)
       
    def getOption (self, number):
        return self._options.get(number)
    
    def _setUriPath(self, segments):
        if isinstance(segments, basestring): #For Python >3.1 replace with isinstance(segments,str)
            raise ValueError("URI Path should be passed as a list or tuple of segments")
        self.deleteOption(number = URI_PATH)
        for segment in segments:
            self.addOption(StringOption(number = URI_PATH, value = str(segment)))
    
    def _getUriPath(self):
        segment_list = []
        uri_path = self.getOption(number = URI_PATH)
        if uri_path is not None:
            for segment in self.getOption(number = URI_PATH):
                segment_list.append(segment.value)
        return segment_list
    
    uri_path = property(_getUriPath, _setUriPath)
        
    def _setBlock2(self, block_tuple):
        self.deleteOption(number = BLOCK2)
        self.addOption(BlockOption(number = BLOCK2, value = block_tuple))
    
    def _getBlock2(self):
        block2 = self.getOption(number = BLOCK2)
        if block2 is not None:
            return block2[0].value
        else:
            return None
    
    block2 = property(_getBlock2, _setBlock2)

    def _setBlock1(self, block_tuple):
        self.deleteOption(number = BLOCK1)
        self.addOption(BlockOption(number = BLOCK1, value = block_tuple))
    
    def _getBlock1(self):
        block1 = self.getOption(number = BLOCK1)
        if block1 is not None:
            return block1[0].value
        else:
            return None
    
    block1 = property(_getBlock1, _setBlock1)
    
    def _setContentFormat(self, content_format):
        self.deleteOption(number = CONTENT_FORMAT)
        self.addOption(UintOption(number = CONTENT_FORMAT, value = content_format))
    
    def _getContentFormat(self):
        content_format = self.getOption(number = CONTENT_FORMAT)
        if content_format is not None:
            return content_format[0].value
        else:
            return None
    
    content_format = property(_getContentFormat, _setContentFormat)

def readExtendedFieldValue(value, rawdata):
    """Used to extract large values of option delta and option length"""
    if value >= 0 and value < 13:
        return (value, rawdata)  
    elif value is 13:
        return (ord(rawdata[0]) + 13, rawdata[1:])
    elif value is 14:
        return (struct.unpack('!H', rawdata[:2])[0] + 269, rawdata[2:])
    else:            
        raise ValueError("Value out of range.")

def writeExtendedFieldValue(value):
    if value >= 0 and value <13:
        return (value, '')
    elif value >= 13 and value < 269:
        return (13, struct.pack('!B', value-13))
    elif value >= 269 and value < 65804:
        return (14, struct.pack('!H', value-269))  
    else:
        raise ValueError("Value out of range.") 


class StringOption(object):
 
    def __init__(self, number, value=""):
        self.value = value
        self.number = number
  
    def encode(self):
        rawdata = self.value
        return rawdata
  
    def decode(self, rawdata):
        self.value = rawdata# if rawdata is not None else ""
  
    def _length(self):
        return len(self.value)
    length = property(_length)
  
class UintOption(object):
 
    def __init__(self, number, value=0):
        self.value = value
        self.number = number
  
    def encode(self):
        rawdata = struct.pack("!L", self.value) #For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(chr(0))
      
    def decode(self, rawdata):                  #For Python >3.1 replace with int.from_bytes()
        value = 0
        for byte in rawdata:
            value = (value * 256) + ord(byte)
        self.value = value
        return self
  
    def _length(self):
        if self.value > 0:
            return (self.value.bit_length()-1)//8+1
        else:
            return 0
    length = property(_length)
    
    
class BlockOption(object):
    BlockwiseTuple = collections.namedtuple('BlockwiseTuple', ['block_number', 'more', 'size_exponent'])
 
    def __init__(self, number, value=(0, None, 0)):
        self.value = self.BlockwiseTuple._make(value)
        self.number = number
  
    def encode(self):
        as_integer = (self.value[0] << 4) + (self.value[1] * 0x08) + self.value[2]
        rawdata = struct.pack("!L", as_integer) #For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(chr(0))
  
    def decode(self, rawdata):
        as_integer = 0
        for byte in rawdata:
            as_integer = (as_integer * 256) + ord(byte)
        self.value = self.BlockwiseTuple(block_number = (as_integer >> 4), more = bool(as_integer & 0x08), size_exponent = (as_integer & 0x07)) 
  
    def _length(self):
        return ((self.value[0].bit_length()+3)/8+1)
    length = property(_length) 
    
option_formats = {6  : UintOption,
                  7  : UintOption,
                  12 : UintOption,
                  14 : UintOption,
                  16 : UintOption,
                  23 : BlockOption,
                  27 : BlockOption,
                  28 : UintOption}  


def isRequest(code):
    return True if (code>=1 and code<32) else False
    
def isResponse(code):
    return True if (code>=64 and code<192) else False

def isSuccessful(code):
    return True if (code>=64 and code<96) else False

def uriPathAsString(segment_list):
    return '/'+'/'.join(segment_list)






class Coap(protocol.DatagramProtocol):

    def __init__ (self, endpoint):
        """Initialize a CoAP endpoint."""
        self.message_id = random.randint(0, 65535)
        self.token = random.randint(0, 65535)
        self.endpoint = endpoint
        self.recent_messages = {}         #recently received messages (identified by message ID and remote)
        self.active_exchanges = {}        #active exchanges i.e. sent CON messages (identified by message ID and remote)
        self.outgoing_requests = {}       #unfinished outgoing requests (identified by token and remote)
        self.incoming_requests = {}       #unfinished incoming requests (identified by URL path and remote)

    def datagramReceived(self, data, (host, port)):
        log.msg("received %r from %s:%d" % (data, host, port))
        message = Message.decode(data, (host,port), self)
        if self.deduplicateMessage(message) is True:
            return
        if isRequest(message.code):
            self.processRequest(message)
        elif isResponse(message.code):
            self.processResponse(message)             
        elif message.code is EMPTY:
            if message.mtype is CON:
                log.msg('Empty CON message received (CoAP Ping) - replying with RST.')
                rst = Message(mtype=RST, mid=message.mid,code=EMPTY, payload='')
                rst.remote = message.remote             
                self.sendMessage(rst)
            #TODO: passing ACK/RESET info to application
            #Currently it doesn't matter if empty ACK or RST is received - in both cases exchange has to be removed
            if message.mid in self.active_exchanges and message.mtype in (ACK, RST):
                self.removeExchange(message)
            

    def deduplicateMessage(self, message):
        key = (message.mid, message.remote)
        log.msg("Incoming Message ID: %d" % message.mid) 
        if key in self.recent_messages:
            if message.mtype is CON:
                #TODO: send a copy of acknowledgement
                log.msg('Duplicate CON received')
            else:
                log.msg('Duplicate NON, ACK or RST received')
            return True      
        else:
            log.msg('New unique message received')
            expiration = reactor.callLater(EXCHANGE_LIFETIME, self.removeMessageFromRecent, key)
            self.recent_messages[key] = (message, expiration)
            return False
    
    def removeMessageFromRecent(self, key):
        self.recent_messages.pop(key)  
    
    def processResponse(self, response):
        if response.mtype is RST:
            return
        if response.mtype is ACK:
            if response.mid in self.active_exchanges:
                self.removeExchange(response)
            else:
                return
        log.msg("Received Response, token: %s, host: %s, port: %s" % (response.token,response.remote[0], response.remote[1]))
        if (response.token, response.remote) in self.outgoing_requests:
            d, timeout_canceller = self.outgoing_requests.pop((response.token, response.remote))
            if response.mtype is CON:
                #TODO: Some variation of sendEmptyACK should be used
                ack = Message(mtype=ACK, mid=response.mid,code=EMPTY, payload="")
                ack.remote = response.remote             
                self.sendMessage(ack)
            timeout_canceller.cancel()
            d.callback(response)
        else:
            log.msg("Response not recognized - sending RST.")
            rst = Message(mtype=RST, mid=response.mid,code=EMPTY, payload='')
            rst.remote = response.remote             
            self.sendMessage(rst)

    def processRequest(self, request):
        if request.mtype not in (CON, NON):
            response = Message(code=BAD_REQUEST, payload='Wrong message type for request!')
            self.respond(response, request)
            return
        if (uriPathAsString(request.opt.uri_path), request.remote) in self.incoming_requests:
            log.msg("Request pertains to earlier blockwise requests.")
            d, canceller = self.incoming_requests.pop((uriPathAsString(request.opt.uri_path), request.remote))
            canceller.cancel()
            d.callback(request)
        else:
            responder = Responder(self, request)

    def sendMessage(self, message):
        """Set Message ID, encode and send message.
           Also if message is Confirmable (CON) add Exchange""" 
        if message.mid is None:
            message.mid = self.nextMessageID()
        if message.mtype is CON:
            self.addExchange(message)
        msg = message.encode()
        self.transport.write(msg, message.remote)
        host, port = message.remote
        log.msg("sent %r to %s:%d" % (msg, host, port))

    def nextMessageID (self):
        """Reserve and return a new message ID."""
        message_id = self.message_id
        self.message_id = 0xFFFF & (1 + self.message_id)
        return message_id
    
    def nextToken (self):
        """Reserve and return a new Token for request."""
        token = self.token
        self.token = 0xFFFF & (1 + self.token)
        return str(token)
    
    def addExchange (self, message):
        timeout = random.uniform(ACK_TIMEOUT, ACK_TIMEOUT * ACK_RANDOM_FACTOR)
        retransmission_counter = 0
        next_retransmission = reactor.callLater(timeout, self.retransmit, message, timeout, retransmission_counter)
        self.active_exchanges[message.mid] = (message, next_retransmission)
        log.msg("Exchange added, Message ID: %d." % message.mid)

    def removeExchange (self, message):
        self.active_exchanges.pop(message.mid)[1].cancel()
        log.msg("Exchange removed, Message ID: %d." % message.mid)
              
    def retransmit (self, message, timeout, retransmission_counter):
        if retransmission_counter < MAX_RETRANSMIT:
            self.transport.write(message.encode(), message.remote)
            retransmission_counter+=1
            timeout*=2
            message.next_retransmission = reactor.callLater(timeout, self.retransmit, message, timeout, retransmission_counter)
        else:
            self.active_exchanges.pop(message.mid)
            #TODO: error handling (especially for requests)

    def request(self, request):
        return Requester(self, request).deferred
        

class Requester(object):
    
    def __init__(self, protocol, app_request):
        self.protocol = protocol
        self.app_request = app_request
        self.assembled_reponse = None
        if isRequest(self.app_request.code) is False:
            raise ValueError("Message code is not valid for request")
        size_exp = DEFAULT_BLOCK_SIZE_EXP
        if len(self.app_request.payload) > (2**(size_exp+4)):
            request = self.app_request.extractBlock(0, size_exp)
        else:
            request = self.app_request
        if request is None:
            return defer.fail()
        self.deferred = self.sendRequest(request)  
        self.deferred.addCallback(self.processBlock1)
        self.deferred.addCallback(self.processBlock2)
        
            
    def sendRequest(self, request): 
        if request.mtype is None:
            request.mtype = CON
        request.token = self.protocol.nextToken()
        self.protocol.sendMessage(request)
        d = defer.Deferred()
        canceller = reactor.callLater(MAX_TRANSMIT_WAIT, self.handleTimedOutRequest, d, request)
        self.protocol.outgoing_requests[(request.token, request.remote)] = (d, canceller)
        log.msg("Sending request - Token: %s, Host: %s, Port: %s" % (request.token, request.remote[0], request.remote[1]))
        return d  

    def processBlock1(self, response):
        if response.opt.block1 is not None:
            block1 = response.opt.block1
            log.msg("Response with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))
            #TODO: compare block size of request and response - calculate new block_number if necessary
            next_block = self.app_request.extractBlock(block1.block_number+1, block1.size_exponent)
            if next_block is not None:
                return self.sendNextRequestBlock(next_block)
            else:
                if block1.more is False:
                    return defer.succeed(response)
                else:
                    return defer.fail()
        else:
            if self.app_request.opt.block1 is None:
                return defer.succeed(response)
            else:
                return defer.fail()

    def sendNextRequestBlock(self, next_block):
        log.msg("Sending next block of blockwise request.")
        d = self.sendRequest(next_block)
        d.addCallback(self.processBlock1)
        return d   

    def processBlock2(self, response):
        if response.opt.block2 is not None:
            block2 = response.opt.block2
            log.msg("Response with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            if self.assembled_reponse is not None:
                log.msg("Appending another block")
                if block2.block_number*(2**(block2.size_exponent+4)) is len(self.assembled_reponse.payload):
                    self.assembled_reponse.payload+=response.payload
                    self.assembled_reponse.opt.block2 = (block2.block_number, block2.more, block2.size_exponent)
                else:
                    log.msg("ProcessBlock2 error: Block received out of order.")
                    return defer.fail()
            else:
                if block2.block_number is 0:
                    log.msg("Receiving blockwise response")  
                    self.assembled_reponse = response
                else:
                    log.msg("ProcessBlock2 error: transfer started with nonzero block number.")
                    return defer.fail()
            if block2.more is True:
                request = self.app_request.generateNextBlock2Request(response)
                return self.askForNextResponseBlock(request)
            else:
                return defer.succeed(self.assembled_reponse)
        else:
            if assembled_response is None:
                return defer.succeed(response)
            else:
                return defer.fail()

    def askForNextResponseBlock(self, request):
        log.msg("Requesting next block of blockwise response.")
        d = self.sendRequest(request)
        d.addCallback(self.processBlock2)
        return d   
    
    def handleTimedOutRequest(self, deferred, request):
        """Clean the Request after a timeout."""
        try:
            del self.protocol.outgoing_requests[(request.token, request.remote)]
        except KeyError:
            pass
        deferred.errback(failure.Failure())
    

class Responder(object):
    
    def __init__(self, protocol, request):
        self.protocol = protocol
        self._assembled_request = None
        self._app_response = None
        log.msg("Request doesn't pertain to earlier blockwise requests.")
        self.d = self.processBlock1(request)
        self.d.addCallback(self.dispatchRequest)#.addErrback(self.handleRenderErrors)

    def processBlock1(self, request):
        if request.opt.block1 is not None:
            block1 = request.opt.block1
            log.msg("Request with Block1 option received, number = %d, more = %d, size_exp = %d." % (block1.block_number, block1.more, block1.size_exponent))
            if block1.block_number is 0:
                #TODO: Check if resource is available - if not send error immediately
                #TODO: Check if method is allowed - if not send error immediately
                if self._assembled_request is not None:
                    log.msg("Incoming blockwise request restarted by client.")
                else:
                    log.msg("New incoming blockwise request.")
                self._assembled_request = request
            else:
                if self._assembled_request is not None:
                    if block1.block_number*(2**(block1.size_exponent+4)) is len(self._assembled_request.payload):
                        self._assembled_request.payload+=request.payload
                        self._assembled_request.opt.block1 = block1
                        self._assembled_request.token = request.token
                        self._assembled_request.mid = request.mid
                    else:
                        #TODO: send an error message - wait for reply from core list
                        log.msg("Request block received out of order.")
                        return defer.fail()
                else:
                    #TODO: send an error message - wait for reply from core list
                    log.msg("Request block received out of order.")
                    return defer.fail()
            if block1.more is True:
                #TODO: SUCCES_CODE Code should be either Changed or Created - Resource check needed 
                #TODO: SIZE_CHECK1 should check if the size of incoming payload is still acceptable 
                #TODO: SIZE_CHECK2 should check if Size option is present, and reject the resource if size too large
                return self.acknowledgeRequestBlock(request)
            else:
                log.msg("Complete blockwise request received.")
                #TODO: using response_type is not very elegant - search for a nicer solution
                self._assembled_request.response_type = None
                return defer.succeed(self._assembled_request)
        else:
            if self._assembled_request is not None:
                log.msg("Non-blockwise request received during blockwise transfer. Blockwise transfer cancelled.")
            return defer.succeed(request)

    def acknowledgeRequestBlock(self, request):
        log.msg("Sending block acknowledgement (allowing client to send next block).")
        response = request.generateNextBlock1Response()
        d = self.sendNonFinalResponse(response, request)
        d.addCallback(self.processBlock1)
        return d

    def dispatchRequest(self, request):
        #TODO: Request with Block2 option and non-zero block number should get error response
        request.prepath = []
        request.postpath = request.opt.uri_path
        resource = self.protocol.endpoint.getResourceFor(request)
        if resource is None:
            raise iot.error.NoResource
        d = resource.render(request)
        delayed_ack = reactor.callLater(EMPTY_ACK_DELAY, self.sendEmptyAck, request)
        d.addCallback(self.respond, request, delayed_ack)
        return d

    def handleRenderErrors(self, err):#, request):
        log.msg("ERRBACK REQUEST ID: %d" % request.mid) 
        err.trap(iot.error.NoResource, iot.error.UnallowedMethod, iot.error.UnsupportedMethod)
        if err.check(iot.error.NoResource):
            log.msg("Dispatch Error: Resource not Found!")
            response = Message(code=NOT_FOUND, payload='Resource not found!')
            self.respond(response, request)
            return
        if err.check(iot.error.UnallowedMethod):
            log.msg("Dispatch Error: Method not allowed!")
            response = Message(code=METHOD_NOT_ALLOWED, payload='Method not allowed!')
            self.respond(response, request)
            return
        if err.check(iot.error.UnsupportedMethod):
            log.msg("Dispatch Error: Method not implemented!")
            response = Message(code=NOT_IMPLEMENTED, payload='Method not implemented!')
            self.respond(response, request)
            return       

    def respond (self, app_response, request, delayed_ack=None):
        log.msg("Preparing response...")  
        if delayed_ack is not None:
            if delayed_ack.active() is True:
                delayed_ack.cancel()
        self._app_response = app_response
        size_exp = min(request.opt.block2.size_exponent if request.opt.block2 is not None else DEFAULT_BLOCK_SIZE_EXP, DEFAULT_BLOCK_SIZE_EXP)
        if len(self._app_response.payload) > (2**(size_exp+4)):
            response = self._app_response.extractBlock(0, size_exp)
            self._app_response.opt.block2 = response.opt.block2
            return self.sendResponseBlock(response, request)
        else:
            self.sendResponse(app_response, request)
            return defer.succeed(None)
        if response is None:
            return defer.fail()
        
    def processBlock2(self, request):
        if request.opt.block2 is not None:
            block2 = request.opt.block2
            log.msg("Request with Block2 option received, number = %d, more = %d, size_exp = %d." % (block2.block_number, block2.more, block2.size_exponent))
            sent_length = (2**(self._app_response.opt.block2.size_exponent+4))*(self._app_response.opt.block2.block_number+1)
            #TODO: compare block size of request and response - calculate new block_number if necessary
            if (2**(block2.size_exponent + 4)) * block2.block_number is sent_length:
                next_block = self._app_response.extractBlock(block2.block_number, block2.size_exponent)
                if next_block is None:
                    log.msg("Block out of range")
                    return defer.fail()
                if next_block.opt.block2.more is True:
                    self._app_response.opt.block2 = next_block.opt.block2
                    return self.sendResponseBlock(next_block, request)
                else:
                    self.sendResponse(next_block, request)
                    return defer.succeed(None)
            else:
                log.msg("Incorrect block number requested")
                return defer.fail()               
        else:
            return defer.fail()

    def sendResponseBlock(self, response_block, request):
        log.msg("Sending response block.")
        d = self.sendNonFinalResponse(response_block, request)
        d.addCallback(self.processBlock2)
        return d

    def sendNonFinalResponse(self, response, request):
        d = defer.Deferred()
        canceller = reactor.callLater(MAX_TRANSMIT_WAIT, self.handleTimedOutClientRequest, d, request)
        self.protocol.incoming_requests[(uriPathAsString(request.opt.uri_path), request.remote)] = (d, canceller)
        self.sendResponse(response, request)
        return d

    def sendResponse(self, response, request):
            
        #if isResponse(response.code) is False:
            #raise ValueError("Message code is not valid for a response.")
        response.token = request.token
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
        log.msg("Sending response, type = %s (request type = %s)" % (types[response.mtype],types[request.mtype]))    
        self.protocol.sendMessage(response)

    def handleTimedOutClientRequest(self, deferred, request):
        """Clean the incoming client request after a timeout."""
        try:
            del self.protocol.incoming_requests[(uriPathAsString(request.opt.uri_path), request.remote)]
        except KeyError:
            pass
        deferred.errback(failure.Failure()) 
      
    def sendEmptyAck (self, request):
        log.msg("Response preparation takes too long - sending empty ACK.")
        ack=Message(mtype=ACK, code=EMPTY, payload="")
        self.respond(ack, request)
