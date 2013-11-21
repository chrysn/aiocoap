'''
Created on 14-09-2013

@author: Maciej Wasilak
'''



#set window size before anything else
from kivy.config import Config
Config.set('graphics', 'height', '1280')
Config.set('graphics', 'width', '720')

import sys

from kivy.support import install_twisted_reactor
from kivy.app import App
from kivy.uix.scrollview import ScrollView
from kivy.uix.button import Button
from kivy.properties import ObjectProperty

# kivy initialization before importing reactor
install_twisted_reactor()

from twisted.internet import reactor
from twisted.python import log

import iot.coap as coap
import iot.resource as resource
import iot.error as error
from widgets.browsingcard import BrowsingCard as BrowsingCard
from widgets.colorboxlayout import ColorBoxLayout as ColorBoxLayout


class Controller(ScrollView):

    address_bar = ObjectProperty()
    label = ObjectProperty()

    def __init__(self, **kwargs):
        super(Controller, self).__init__(**kwargs)
        self.protocol = kwargs['protocol']

    def send_request(self, *args):
        log.msg("send request")
        request = coap.Message(code=coap.GET)
        card = BrowsingCard(controller=self)
        self.grid.add_widget(card)
        try:
            request.parseURI(self.address_bar.text)
            card.lbl.text = "GET " + self.address_bar.text
        except None:
            card.btn.text = "Error parsing URI!!!"
        else:
            try:
                card.deferred = self.protocol.request(request)
            except:
                card.btn.text = "Error sending request!!!"
            else:
                card.deferred.addCallback(self.print_response, card).addErrback(self.print_error, card)

    def print_response(self, response, card):
        card.btn.text = 'Response: ' + response.payload

    def print_error(self, err, card):
        err.trap(error.RequestTimedOut, card)
        card.btn.text = 'Request timed out!'

    def close_card(self, animation, card):
        if hasattr(card, 'deferred') is True:
            card.deferred.cancel()
        self.grid.remove_widget(card)


class CoapBrowserApp(App):

    def build(self):
        self.create_protocol()
        return Controller(protocol=self.protocol)

    def create_protocol(self):
        endpoint = resource.Endpoint(None)
        self.protocol = coap.Coap(endpoint)
        #try:
        reactor.listenUDP(61616, self.protocol)#, interface="::")
        #except:
        #    pass


if __name__ == '__main__':
    log.startLogging(sys.stdout)
    CoapBrowserApp().run()







