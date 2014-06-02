'''
Created on 08-09-2012

@author: Maciej Wasilak
'''
import struct
import random
import copy
import sys

from twisted.internet.defer import Deferred
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

import iot.coap as coap
import iot.resource as resource


class Agent():
    """
    Example class which performs single PUT request to localhost
    port 5683 (official IANA assigned CoAP port), URI "/other/block".
    Request is sent 2 seconds after initialization.

    Payload is bigger than 64 bytes, and with default settings it
    should be sent as several blocks.
    """

    def __init__(self, protocol):
        self.protocol = protocol
        reactor.callLater(2, self.put_resource)

    def put_resource(self):
        payload = "Poland CAN into space!!! Poland MUST into space!!! Poland WILL into space!!!!"
        request = coap.Message(code=coap.PUT, payload=payload)
        request.opt.uri_path = ("other", "block")
        request.remote = ('127.0.0.1', coap.COAP_PORT)
        d = protocol.request(request)
        d.addCallback(self.print_response)

    def print_response(self, response):
        print('Result: ' + response.payload)

logging.basicConfig(level=logging.INFO)

endpoint = resource.Endpoint(None)
protocol = coap.Coap(endpoint)
client = Agent(protocol)

reactor.listenUDP(61616, protocol)
reactor.run()
