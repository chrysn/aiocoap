# This file is part of the txThings project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# txThings is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

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

endpoint = resource.Site(None)
protocol = coap.CoAP(endpoint)
client = Agent(protocol)

reactor.listenUDP(61616, protocol)
reactor.run()
