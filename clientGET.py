'''
Created on 08-09-2012

@author: Maciej Wasilak
'''
import struct
import random
import copy
import sys

import logging

from twisted.internet.defer import Deferred
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

import iot.coap as coap
import iot.resource as resource


class Agent():
    """
    Example class which performs single GET request to localhost
    port 5683 (official IANA assigned CoAP port), URI "/other/separate".
    Request is sent 2 seconds after initialization.

    Method requestResource constructs the request message to
    remote endpoint. Then it sends the message using protocol.request().
    A deferred 'd' is returned from this operation.

    Deferred 'd' is fired internally by protocol, when complete response is received.

    Method printResponse is added as a callback to the deferred 'd'. This
    method's main purpose is to act upon received response (here it's simple print).
    """

    def __init__(self, protocol):
        self.protocol = protocol
        reactor.callLater(2, self.requestResource)

    def requestResource(self):
        request = coap.Message(code=coap.GET)
        #request.opt.uri_path = ('other', 'separate')
        request.opt.uri_path = ('time',)
        request.remote = ("127.0.0.1", coap.COAP_PORT)
        request.opt.observe = 0

        # this would be usually done as self.protocol.request(request, o...),
        # but we need to access the observation to cancel it
        requester = coap.Requester(self.protocol, request, observeCallback=self.printLaterResponse, block1Callback=None, block2Callback=None, observeCallbackArgs=None, block1CallbackArgs=None, block2CallbackArgs=None, observeCallbackKeywords=None, block1CallbackKeywords=None, block2CallbackKeywords=None)
        self.observation = requester.observation
        reactor.callLater(15, self.stopObserving)
        d = requester.deferred

        d.addCallback(self.printResponse)
        d.addErrback(self.noResponse)

    def printResponse(self, response):
        print('Result: ' + response.payload)
        #reactor.stop()

    def printLaterResponse(self, response):
        print('Newer result: ' + response.payload)

    def noResponse(self, failure):
        print('Failed to fetch resource:')
        print(failure)
        #reactor.stop()

    def stopObserving(self):
        print('Not interested in the resource any more, staying alive for some time to see the observation results bounce back')
        self.observation.cancel()

        reactor.callLater(10, reactor.stop)

logging.basicConfig(level=logging.INFO)

endpoint = resource.Endpoint(None)
protocol = coap.Coap(endpoint)
client = Agent(protocol)

reactor.listenUDP(61616, protocol)
reactor.run()
