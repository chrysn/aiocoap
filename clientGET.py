# This file is part of the Python aiocoap library project.
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

import logging

import socket
import asyncio

import aiocoap
import aiocoap.resource as resource

class Agent():
    """
    Example class which performs single GET request to localhost
    port 5683 (official IANA assigned CoAP port), URI "/other/separate".
    Request is sent 2 seconds after initialization.

    Method request_resource constructs the request message to
    remote endpoint. Then it sends the message using protocol.request().
    A deferred 'd' is returned from this operation.

    Deferred 'd' is fired internally by protocol, when complete response is received.

    Method print_response is added as a callback to the deferred 'd'. This
    method's main purpose is to act upon received response (here it's simple print).
    """

    def __init__(self, protocol):
        self.protocol = protocol

    @asyncio.coroutine
    def run(self):
        yield from self.request_resource()

        print("Waiting for other results to our observation to arrive")
        yield from asyncio.sleep(40)

    @asyncio.coroutine
    def request_resource(self):
        request = aiocoap.Message(code=aiocoap.GET)
        #request.opt.uri_path = ('other', 'separate')
        request.opt.uri_path = ('time',)
        request.remote = ("127.0.0.1", aiocoap.COAP_PORT)
        request.opt.observe = 0

        # this would be usually done as self.protocol.request(request, o...),
        # but we need to access the observation to cancel it
        requester = aiocoap.protocol.Requester(self.protocol, request)
        self.observation = requester.observation
        self.observation.register_callback(self.print_later_response)

        try:
            response = yield from requester.response
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
        else:
            print('Result: %s %r'%(response.code, response.payload))
            self.protocol.loop.call_later(15, self.stop_observing)

    def print_later_response(self, response):
        print('Newer result: %r'%response.payload)

    def stop_observing(self):
        print('Not interested in the resource any more.')
        self.observation.cancel()

logging.getLogger("").setLevel(logging.DEBUG)
logging.getLogger("asyncio").setLevel(logging.INFO)
logging.getLogger("coap").setLevel(logging.INFO)
logging.debug("clientGET started")

loop = asyncio.get_event_loop()

transport, protocol = loop.run_until_complete(loop.create_datagram_endpoint(aiocoap.Endpoint, family=socket.AF_INET))
# use the following lines instead, and change the address to `::ffff:127.0.0.1`
# in order to see acknowledgement handling fail with hybrid stack operation
#transport, protocol = loop.run_until_complete(loop.create_datagram_endpoint(aiocoap.Endpoint, family=socket.AF_INET6))
#transport._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
client = Agent(protocol)

loop.run_until_complete(client.run())
