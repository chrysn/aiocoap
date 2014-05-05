'''
Created on 08-09-2012

@author: Maciej Wasilak
'''
import struct
import random
import copy
import sys

import logging

import asyncio

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

    @asyncio.coroutine
    def run(self):
        self.completed = asyncio.Future()
        self.protocol.loop.call_later(2, self.requestResource)

        yield from self.completed

        print("Waiting for other results to our observation to arrive")
        yield from asyncio.sleep(40)

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
        self.protocol.loop.call_later(15, self.stopObserving)
        d = requester.response

        d.add_done_callback(self.printResponse)

    def printResponse(self, response_future):
        try:
            response = response_future.result()
        except Exception as e:
            self.noResponse(e)
            return

        print('Result: %r'%response.payload)
        self.completed.set_result(None)

    def printLaterResponse(self, response):
        print('Newer result: %r'%response.payload)

    def noResponse(self, failure):
        print('Failed to fetch resource:')
        print(failure)
        self.completed.set_result(None)

    def stopObserving(self):
        print('Not interested in the resource any more.')
        self.observation.cancel()

logging.getLogger("").setLevel(logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.INFO)
logging.getLogger("coap").setLevel(logging.INFO)
logging.debug("clientGET started")

loop = asyncio.get_event_loop()

endpoint = resource.Endpoint(None)
transport, protocol = loop.run_until_complete(loop.create_datagram_endpoint(lambda: coap.Coap(endpoint, loop), ('127.0.0.1', 61616)))
client = Agent(protocol)

loop.run_until_complete(client.run())
