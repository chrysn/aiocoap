'''
Created on 14-09-2013

@author: Maciej Wasilak

This is an example Kivy + txThings application.
It is a simple CoAP browser, that allows sending
requests to a chosen IP address

Currently only plain IPv4 addresses are supported. No URI support.
'''



#set window size before anything else
from kivy.config import Config
Config.set('graphics', 'height', '1280')
Config.set('graphics', 'width', '720')

import socket
import sys
import re
from urlparse import urlsplit as urlsplit, urlunsplit

from kivy.support import install_twisted_reactor
from kivy.app import App
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.uix.spinner import Spinner
from kivy.uix.treeview import TreeView, TreeViewNode
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.properties import ObjectProperty, OptionProperty, ListProperty
from kivy.core.window import Window
Window.clearcolor = (0, 0, 0, 1)
# kivy initialization before importing reactor
install_twisted_reactor()

from twisted.internet import reactor, defer, threads
from twisted.python import log

import iot.coap as coap
import iot.resource as resource
import iot.error as error
from widgets.browsingcard import BrowsingCard as BrowsingCard

import link_header

#Netloc parser assembled from various bits on stack overflow and regexlib
NETLOC_RE = re.compile(r'''^
                        (?:([^@])+@)?
                        (?:\[((?:(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|
                        (?:(?:[0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|
                        (?:(?:[0-9A-Fa-f]{1,4}:){5}:(?:[0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|
                        (?:(?:[0-9A-Fa-f]{1,4}:){4}:(?:[0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|
                        (?:(?:[0-9A-Fa-f]{1,4}:){3}:(?:[0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|
                        (?:(?:[0-9A-Fa-f]{1,4}:){2}:(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|
                        (?:(?:[0-9A-Fa-f]{1,4}:){6}(?:(?:\b(?:(?:25[0-5])|(?:1\d{2})|(?:2[0-4]\d)|
                        (?:\d{1,2}))\b)\.){3}(?:\b(?:(?:25[0-5])|
                        (?:1\d{2})|(?:2[0-4]\d)|(?:\d{1,2}))\b))|
                        (?:(?:[0-9A-Fa-f]{1,4}:){0,5}:(?:(?:\b(?:(?:25[0-5])|
                        (?:1\d{2})|(?:2[0-4]\d)|(?:\d{1,2}))\b)\.){3}(?:\b(?:(?:25[0-5])|
                        (?:1\d{2})|(?:2[0-4]\d)|(?:\d{1,2}))\b))|
                        (?:::(?:[0-9A-Fa-f]{1,4}:){0,5}(?:(?:\b(?:(?:25[0-5])|
                        (?:1\d{2})|(?:2[0-4]\d)|(?:\d{1,2}))\b)\.){3}(?:\b(?:(?:25[0-5])|
                        (?:1\d{2})|(?:2[0-4]\d)|(?:\d{1,2}))\b))|(?:[0-9A-Fa-f]{1,4}::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|
                        (?:::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(?:(?:[0-9A-Fa-f]{1,4}:){1,7}:)))\]|
                        ((?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|
                        ((?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])))
                        (?::(\d+))?$
                        ''', re.VERBOSE)

def parseURI(uri_string):
    """
    Parse an URI into five components and set appropriate
    options.
    """
    #TODO: Don't know why Twisted Web forbids unicode strings - check that
    #if isinstance(uri_string, unicode):
    #    raise TypeError("uri must be str, not unicode")
    scheme, netloc, path, query, fragment = urlsplit(uri_string)
    if isinstance(scheme, unicode):
        scheme = scheme.encode('ascii')
        netloc = netloc.encode('ascii')
        path = path.encode('ascii')
        query = query.encode('ascii')
        fragment = fragment.encode('ascii')
    if fragment != "":
        raise ValueError('Error: URI fragment should be ""')
    match = NETLOC_RE.match(netloc)
    if match:
        if match.group(5):
            port = int(match.group(5))
        else:
            port = coap.COAP_PORT
        if match.group(2):
            host = match.group(2)
            return defer.succeed([(scheme, host, port, path, query)])
        elif match.group(3):
            #host = "::ffff:"+match.group(3)
            host = match.group(3)
            return defer.succeed([(scheme, host, port, path, query)])
        elif match.group(4):
            print match.group(4)
            #d = client.getHostByName(match.group(4))
            d = threads.deferToThread(socket.getaddrinfo, match.group(4), port, 0, socket.SOCK_DGRAM)
            d.addCallback(process_name, (scheme, port, path, query))
            return d
    return defer.fail('Error: URI netloc invalid')

def process_name(gaiResult, netloc_fragments):
    scheme, port, path, query = netloc_fragments
    for family, socktype, proto, canonname, sockaddr in gaiResult:
        if family in [socket.AF_INET6]:
            yield (scheme, sockaddr[0],port, path, query)
        elif family in [socket.AF_INET]:
            yield (scheme, "::ffff:"+sockaddr[0],port, path, query)
    #host = "::ffff:"+result
    #print "Host:", host
    #return (scheme, host, port, path, query)

class ResponseCard(BrowsingCard):

    def __init__(self, **kwargs):
        super(ResponseCard, self).__init__(**kwargs)
        self.response = None

    def open_message_popup(self):
        if self.response is not None:
            if self.response.opt.content_format is coap.media_types_rev['application/link-format']:
                content = BoxLayout(orientation='vertical')
                content.add_widget(Button(text='Process link format',on_release=self.process_link_format))
                self.controller.popup.content = content
                self.controller.popup.open()

    def process_link_format(self, button):
        link_list = link_header.parse(self.response.payload)
        self.controller.screen_manager.get_screen('nodes').add_link_list(link_list, self.request_uri)
        self.controller.popup.dismiss()



class MainScreen(Screen):

    address_bar = ObjectProperty()
    label = ObjectProperty()
    active_method = OptionProperty('GET', options=('GET', 'PUT', 'POST', 'DELETE'))


    def __init__(self, **kwargs):
        super(MainScreen, self).__init__(**kwargs)
        self.protocol = kwargs['protocol']
        self.screen_manager = kwargs['screen_manager']
        self.method_chooser = MethodPanel(controller=self)
        self.method_chooser_visible = False
        self.popup = Popup(title='Actions',
           content=Label(text=''),
           size_hint=(None, None), size=(400, 400))

    def toggle_method_chooser(self):
        if self.method_chooser_visible is False:
            self.method_chooser_visible = True
            self.menu_wrapper.add_widget(self.method_chooser)
        else:
            self.method_chooser_visible = False
            self.menu_wrapper.remove_widget(self.method_chooser)

    def set_active_method(self, method):
        self.active_method = method
        self.method_button.text = method

    def prepare_request(self, *args):
        card = ResponseCard(controller=self)
        self.grid.add_widget(card)
        log.msg("send request %s" % self.active_method)
        card.request = coap.Message()
        card.request.code = coap.requests_rev[self.active_method]
        card.request_uri = self.address_bar.text
        card.target_uri.text = self.active_method + ' ' + self.address_bar.text
        if card.request.code is coap.GET:
            accept = self.method_chooser.accept_field.text
            if accept in coap.media_types_rev:
                card.request.opt.accept = coap.media_types_rev[accept]
            observe = self.method_chooser.observe_field.active
            if observe is True:
                card.request.setObserve(self.process_update, card)
        if card.request.code is coap.PUT:
            payload =  self.method_chooser.put_payload_box.text
            payload = payload.encode('utf-8')
            card.request.payload = payload
            content_format = self.method_chooser.content_format_put_field.text
            if content_format in coap.media_types_rev:
                card.request.opt.content_format = coap.media_types_rev[content_format]
        if card.request.code is coap.POST:
            payload =  self.method_chooser.post_payload_box.text
            payload = payload.encode('utf-8')
            card.request.payload = payload
            content_format = self.method_chooser.content_format_post_field.text
            if content_format in coap.media_types_rev:
                card.request.opt.content_format = coap.media_types_rev[content_format]
        card.deferred = parseURI(self.address_bar.text).addErrback(self.handle_DNS_failure, card).addCallback(self.send_request, card)

    def handle_DNS_failure(self, card):
        log.msg("DNS Error - host not found")
        card.response_payload.text = "DNS error: host not found!!!"

    def send_request(self, result, card):
        for scheme, host, port, path, query in result:
            if scheme != "coap":
                card.response_payload.text = 'Error: URI scheme should be "coap"'
            card.request.remote = (host, port)
            if path != "" and path != "/":
                path = path.lstrip("/")
                card.request.opt.uri_path = path.split("/")
            if query != "":
                card.request.opt.uri_query = query.split("&")
            try:
                deferred = self.protocol.request(card.request, self.block1_callback, self.block2_callback)
            except:
                card.response_payload.text = "Error sending request!!!"
            else:
                return deferred.addCallback(self.process_response, card).addErrback(self.print_error, card)

    def block1_callback(self):
        return defer.succeed(True)

    def block2_callback(self):
        return defer.succeed(True)

    def process_response(self, response, card):
        card.response = response
        card.response_code.text = '[b]Code:[/b] ' + coap.responses[card.response.code]
        card.message_type.text = "[b]Type:[/b] " + coap.types[card.response.mtype]
        card.message_type.text += " [b]ID:[/b] " + str(card.response.mid)
        card.message_type.text += " [b]Token:[/b] " + card.response.token.encode('hex')
        formatted_options = "[b]Options:[/b]"
        for option in card.response.opt.optionList():
            formatted_options += "\n- "
            if option.number in coap.options:
                formatted_options += coap.options[option.number]
            else:
                formatted_options += "Unknown"
            formatted_options += " (" + str(option.number) + ")"
            if option.value is not None:
                formatted_options += " : " + str(option.value)
        card.option_list.text = formatted_options
        card.response_payload.text = 'Response: ' + card.response.payload

    def process_update(self, response, card):
        self.process_response(response, card)

    def print_error(self, err, card):
        err.trap(error.RequestTimedOut, card)
        card.response_payload.text = 'Request timed out!'

    def close_card(self, animation, card):
        if hasattr(card, 'deferred') is True:
            card.deferred.cancel()
        card.controller = None
        self.grid.remove_widget(card)

    def open_nodes_screen(self):
        self.screen_manager.transition.direction = 'right'
        self.screen_manager.current = 'nodes'

class TabbedPanelContentGrid(GridLayout):
    '''Default TabbedPanelContent class inherits from FloatLayout.
       It is hard to automatically update its height after switching tabs.

       This new class inherits from Grid Layout, so it is easy to update
       its height.
    '''
    pass

class MethodPanel(TabbedPanel):

    def __init__(self, **kwargs):
        self.accept_field_values = coap.media_types.values()
        self.accept_field_values.append('none')
        print self.accept_field_values
        super(MethodPanel, self).__init__(**kwargs)
        self.controller = kwargs['controller']
        #In next line original TabbedPanelContent object is replaced
        #by custom made TabbedPanelContentGrid object
        self.content = TabbedPanelContentGrid()
        self.content.bind(height=self.update_height)
        self.bind(tab_height=self.update_height)

    def update_height(self, obj, value):
        """This is a setter for height"""
        #This method is necessary because using kv file does not work properly
        self.height = self.content.height + self.tab_height

class FlatButton(Button):
    background_normal = ListProperty([.5, .5, .5, .5])
    background_down = ListProperty([1, 1, 1, 1])

class NodeLabel(Label, TreeViewNode):
    pass

class NodesScreen(Screen):

    def __init__(self, **kwargs):
        super(NodesScreen, self).__init__(**kwargs)
        self.screen_manager = kwargs['screen_manager']
        self.discoveries = {}

    def add_link_list(self, link_list, request_uri):
        self.discoveries[request_uri] = link_list
        source_node = self.tree_view.add_node(NodeLabel(text=request_uri))
        for link in link_list.links:
            link_txt = '[ref=world]' + link.href + '[/ref]'
            link_node = self.tree_view.add_node(NodeLabel(text=link_txt), source_node)
            link_node.link = link
            link_node.bind(on_ref_press=self.choose_link)
            for attribute in link.attr_pairs:
                if attribute[1] is not None:
                    attr_txt = "[color=00ffff][b]" + attribute[0] + " = [/b][/color][color=0066ff]" + attribute[1] + "[/color]"
                else:
                    attr_txt = "[color=00ffff][b]" + attribute[0] + "[/b][/color]"
                self.tree_view.add_node(NodeLabel(text=attr_txt), link_node)

    def choose_link(self, link_node, value):
        scheme, netloc, path, query, fragment = urlsplit(link_node.link.href)
        if scheme == "" and netloc == "":
            #relative URI
            if link_node.link.rel is None or link_node.link.rel is "hosts":
                #Using default realtion "hosts"
                p_scheme, p_netloc, p_path, p_query, p_fragment = urlsplit(link_node.parent_node.text)
                target_uri = urlunsplit((p_scheme, p_netloc, path, query, fragment))
        else:
            target_uri = link_node.link.href
        self.screen_manager.get_screen('controller').address_bar.text = target_uri
        log.msg("Put link %s into browser address box" % target_uri)
        self.open_main_screen()

    def open_main_screen(self):
        self.screen_manager.transition.direction = 'left'
        self.screen_manager.current = 'controller'

class CoapBrowserApp(App):

    def build(self):
        self.create_protocol()
        sm = ScreenManager(transition=SlideTransition())
        sm.add_widget(MainScreen(name='controller', protocol=self.protocol, screen_manager=sm))
        sm.add_widget(NodesScreen(name='nodes', screen_manager=sm))
        return sm

    def create_protocol(self):
        endpoint = resource.Endpoint(None)
        self.protocol = coap.Coap(endpoint)
        reactor.listenUDP(61616, self.protocol)#, interface="::")


    def on_pause(self):
        return True

    def on_resume(self):
        pass

if __name__ == '__main__':
    log.startLogging(sys.stdout)
    CoapBrowserApp().run()







