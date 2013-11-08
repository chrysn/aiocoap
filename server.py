'''
Created on 08-09-2012

@author: Maciej Wasilak
'''
import struct
import random
import copy
import sys
import datetime

from twisted.internet import defer
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.python import log

import iot.resource as resource
import iot.coap as coap


class CounterResource (resource.CoAPResource):
    """
    Example Resource which supports only GET method. Response is a
    simple counter value.

    Name render_<METHOD> is required by convention. Such method should
    return a Deferred. If the result is available immediately it's best
    to use Twisted method defer.succeed(msg).
    """
   #isLeaf = True

    def __init__(self, start=0):
        resource.CoAPResource.__init__(self)
        self.counter = start
        self.visible = True
        self.addParam(resource.LinkParam("title", "Counter resource"))

    def render_GET(self, request):
        response = coap.Message(code=coap.CONTENT, payload='%d' % (self.counter,))
        self.counter += 1
        return defer.succeed(response)


class BlockResource (resource.CoAPResource):
    """
    Example Resource which supports GET, and PUT methods. It sends large
    responses, which trigger blockwise transfer (>64 bytes for normal
    settings).

    As before name render_<METHOD> is required by convention.
    """
    #isLeaf = True

    def __init__(self):
        resource.CoAPResource.__init__(self)
        self.visible = True

    def render_GET(self, request):
        payload=" Now I lay me down to sleep, I pray the Lord my soul to keep, If I shall die before I wake, I pray the Lord my soul to take."
        response = coap.Message(code=coap.CONTENT, payload=payload)
        return defer.succeed(response)

    def render_PUT(self, request):
        print 'PUT payload: ' + request.payload
        payload = "Mr. and Mrs. Dursley of number four, Privet Drive, were proud to say that they were perfectly normal, thank you very much."
        response = coap.Message(code=coap.CHANGED, payload=payload)
        return defer.succeed(response)


class SeparateLargeResource(resource.CoAPResource):
    """
    Example Resource which supports GET method. It uses callLater
    to force the protocol to send empty ACK first and separate response
    later. Sending empty ACK happens automatically after coap.EMPTY_ACK_DELAY.
    No special instructions are necessary.

    Method render_GET returns a deferred. This allows the protocol to
    do other things, while the answer is prepared.

    Method responseReady uses d.callback(response) to "fire" the deferred,
    and send the response.
    """
    #isLeaf = wTrue

    def __init__(self):
        resource.CoAPResource.__init__(self)
        self.visible = True
        self.addParam(resource.LinkParam("title", "Large resource."))

    def render_GET(self, request):
        d = defer.Deferred()
        reactor.callLater(3, self.responseReady, d, request)
        return d

    def responseReady(self, d, request):
        print 'response ready. sending...'
        payload = "Three rings for the elven kings under the sky, seven rings for dwarven lords in their halls of stone, nine rings for mortal men doomed to die, one ring for the dark lord on his dark throne."
        response = coap.Message(code=coap.CONTENT, payload=payload)
        d.callback(response)

class TimeResource(resource.CoAPResource):
    def __init__(self):
        resource.CoAPResource.__init__(self)
        self.visible = True
        self.observable = True

        self.notify()

    def notify(self):
        print "i'm trying to send notifications"
        self.updatedState()
        reactor.callLater(60, self.notify)

    def render_GET(self, request):
        response = coap.Message(code=coap.CONTENT, payload=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
        return defer.succeed(response)

class CoreResource(resource.CoAPResource):
    """
    Example Resource that provides list of links hosted by a server.
    Normally it should be hosted at /.well-known/core

    Resource should be initialized with "root" resource, which can be used
    to generate the list of links.

    For the response, an option "Content-Format" is set to value 40,
    meaning "application/link-format". Without it most clients won't
    be able to automatically interpret the link format.

    Notice that self.visible is not set - that means that resource won't
    be listed in the link format it hosts.
    """

    def __init__(self, root):
        resource.CoAPResource.__init__(self)
        self.root = root

    def render_GET(self, request):
        data = []
        self.root.generateResourceList(data, "")
        payload = ",".join(data)
        print payload
        response = coap.Message(code=coap.CONTENT, payload=payload)
        response.opt.content_format = 40
        return defer.succeed(response)

# Resource tree creation
log.startLogging(sys.stdout)
root = resource.CoAPResource()

well_known = resource.CoAPResource()
root.putChild('.well-known', well_known)
core = CoreResource(root)
well_known.putChild('core', core)

counter = CounterResource(5000)
root.putChild('counter', counter)

time = TimeResource()
root.putChild('time', time)

other = resource.CoAPResource()
root.putChild('other', other)

block = BlockResource()
other.putChild('block', block)

separate = SeparateLargeResource()
other.putChild('separate', separate)

endpoint = resource.Endpoint(root)
reactor.listenUDP(coap.COAP_PORT, coap.Coap(endpoint))
reactor.run()
