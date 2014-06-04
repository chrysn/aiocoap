'''
Created on 14-09-2013

@author: Maciej Wasilak
'''

import sys

from kivy.support import install_twisted_reactor
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout

# kivy initialization before importing reactor
install_twisted_reactor()

from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log

import iot.resource as resource
import iot.coap as coap


class MOTDResource (resource.CoAPResource):
    """
    Example Resource which supports only GET method. Response is a
    text from textbox on the main screen (Message of the Day)".

    Name render_<METHOD> is required by convention. Such method should
    return a Deferred. If the result is available immediately it's best
    to use Twisted method defer.succeed(msg).
    """
   #isLeaf = True

    def __init__(self, app, start=0):
        resource.CoAPResource.__init__(self)
        self.app = app
        self.counter = start
        self.visible = True
        self.add_param(resource.LinkParam("title", "MOTD resource"))

    def render_GET(self, request):
        response = coap.Message(code=coap.CONTENT, payload='%s' % str(self.app.messagebox.text))
        self.counter += 1
        self.app.display_counter(self.counter)
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
        self.root.generate_resource_list(data, "")
        payload = ",".join(data)
        print(payload)
        response = coap.Message(code=coap.CONTENT, payload=payload)
        response.opt.content_format = 40
        return defer.succeed(response)


class TwistedServerApp(App):

    def build(self):
        # Resource tree creation
        root = resource.CoAPResource()

        well_known = resource.CoAPResource()
        root.put_child('.well-known', well_known)
        core = CoreResource(root)
        well_known.put_child('core', core)

        counter = MOTDResource(self, 0)
        root.put_child('motd', counter)

        endpoint = resource.Site(root)
        reactor.listenUDP(coap.COAP_PORT, coap.CoAP(endpoint))

        # Kivy screen initialization
        self.label = Label(text="")
        self.display_counter(0)
        self.messagebox = TextInput(size_hint_y=.1, multiline=False)
        self.messagebox.text = "Message of the day"
        self.layout = BoxLayout(orientation='vertical', padding=10)
        self.layout.add_widget(self.label)
        self.layout.add_widget(self.messagebox)
        return self.layout

    def display_counter(self, count):
        self.label.text  = "requests received: %d\n" % count



if __name__ == '__main__':
    log.startLogging(sys.stdout)
    TwistedServerApp().run()

