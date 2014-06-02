'''
Created on 14-09-2013

@author: Maciej Wasilak

This is an example Kivy + txThings application.
It is a simple CoAP browser, that allows sending
requests to a chosen IP address

Currently only plain IPv4 addresses are supported. No URI support.
'''



import socket
import sys
import re
import copy
import cPickle
from urlparse import urlsplit, urlunsplit

from kivy.support import install_twisted_reactor
from kivy.app import App
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.uix.spinner import Spinner, SpinnerOption
from kivy.uix.treeview import TreeView, TreeViewNode
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.properties import ObjectProperty, OptionProperty, ListProperty
from kivy.core.window import Window
Window.clearcolor = (1, 1, 1, 1)
# kivy initialization before importing reactor
install_twisted_reactor()

from twisted.internet import reactor, defer, threads, task
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

class InvalidURI(Exception):
    """Raised when URI is not valid."""

class FragmentNotAllowed(Exception):
    """Raised when URI contains fragment marker."""

def parse_u_r_i(uri_string):
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

    p_list = path.split("?")
    if len(p_list) > 0:
        path = p_list[0]
    if len(p_list) > 1:
        query = p_list[1]
    if len(p_list) > 2:
        return defer.fail(InvalidURI())
    if "#" in path or "#" in query:
        return defer.fail(FragmentNotAllowed())
    match = NETLOC_RE.match(netloc)
    if match:
        if match.group(5):
            port = int(match.group(5))
        else:
            port = coap.COAP_PORT
        if match.group(2):
            host = match.group(2)
            return defer.succeed(iter([(scheme, host, port, path, query)]))
        elif match.group(3):
            host = "::ffff:"+match.group(3)
            return defer.succeed(iter([(scheme, host, port, path, query)]))
        elif match.group(4):
            d = threads.deferToThread(socket.getaddrinfo, match.group(4), port, 0, socket.SOCK_DGRAM)
            d.addCallback(process_name, (scheme, port, path, query))
            return d
    return defer.fail(InvalidURI())

def process_name(gaiResult, netloc_fragments):
    scheme, port, path, query = netloc_fragments
    for family, socktype, proto, canonname, sockaddr in gaiResult:
        if family in [socket.AF_INET6]:
            yield (scheme, sockaddr[0],port, path, query)
    for family, socktype, proto, canonname, sockaddr in gaiResult:
        if family in [socket.AF_INET]:
            yield (scheme, "::ffff:"+sockaddr[0], port, path, query)

class PopupButton(Button):
    pass

class ResponseCard(BrowsingCard):

    def __init__(self, **kwargs):
        super(ResponseCard, self).__init__(**kwargs)
        self.response = None

    def open_message_popup(self):
        if self.response is not None:
            content = BoxLayout(orientation='vertical', spacing=5)
            content.add_widget(PopupButton(text='Add bookmark',on_release=self.add_bookmark))
            if self.response.opt.content_format is coap.media_types_rev['application/link-format']:
                content.add_widget(PopupButton(text='Process link format',on_release=self.process_link_format))
            self.controller.popup.content = content
            self.controller.popup.open()

    def process_link_format(self, button):
        self.controller.screen_manager.get_screen('nodes').add_link_list(self.response.payload, self.request_uri)
        self.controller.popup.dismiss()

    def add_bookmark(self, button):
        self.controller.screen_manager.get_screen('nodes').add_bookmark(self.request_uri)
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

    def prepare_request(self, *args):
        card = ResponseCard(controller=self)
        self.grid.add_widget(card)
        log.msg("send request %s" % self.active_method)
        request = coap.Message()
        request.code = coap.requests_rev[self.active_method]
        card.target_uri.text = self.active_method + ' ' + self.address_bar.text
        card.request_uri = self.address_bar.text
        if request.code is coap.GET:
            accept = self.method_chooser.accept_field.text
            if accept in coap.media_types_rev:
                request.opt.accept = coap.media_types_rev[accept]
            observe = self.method_chooser.observe_field.active
            if observe is True:
                request.opt.observe = 0
        if request.code is coap.PUT:
            payload =  self.method_chooser.put_payload_box.text
            payload = payload.encode('utf-8')
            request.payload = payload
            content_format = self.method_chooser.content_format_put_field.text
            if content_format in coap.media_types_rev:
                request.opt.content_format = coap.media_types_rev[content_format]
        if request.code is coap.POST:
            payload =  self.method_chooser.post_payload_box.text
            payload = payload.encode('utf-8')
            request.payload = payload
            content_format = self.method_chooser.content_format_post_field.text
            if content_format in coap.media_types_rev:
                request.opt.content_format = coap.media_types_rev[content_format]
        d = parse_u_r_i(self.address_bar.text)
        d.addCallback(self.send_request, card, request)
        d.addCallback(self.process_response, card)
        d.addErrback(self.print_error, card)
        card.deferred = d

    def send_request(self, result, card, request):

        def block1_callback(response, deferred):
            if response.code is coap.CONTINUE:
                for d in pending:
                    if d is not deferred:
                        d.cancel()
                    if lc.running:
                        lc.stop()
            return defer.succeed(True)

        def block2_callback(response, deferred):
            if response.code is coap.CONTENT:
                for d in pending:
                    if d is not deferred:
                        d.cancel()
                    if lc.running:
                        lc.stop()
            return defer.succeed(True)

        def remove_from_pending(response, deferred):
            pending.remove(deferred)
            return response

        def set_winner(response):
            if lc.running:
                lc.stop()

            successful.append(True)
            for d in pending:
                d.cancel()
            winner.callback(response)
            return None

        def check_done():
            if dns_result_list_exhausted and not pending and not successful:
                winner.errback(failures.pop())

        def request_failed(reason):
            failures.append(reason)
            check_done()
            return None

        def cancel_request(d):
            for d in pending:
                d.cancel()

        def iterate_requests():
            try:
                scheme, host, port, path, query = next(result)
            except StopIteration:
                lc.stop()
                dns_result_list_exhausted.append(True)
                check_done()
            else:
                card.response_payload.text += "\nRequest to %s" % host
                request_copy = copy.deepcopy(request)
                if scheme != "coap":
                    card.response_payload.text += 'Error: URI scheme should be "coap"'
                request_copy.remote = (host, port)
                if path != "" and path != "/":
                    path = path.lstrip("/")
                    request_copy.opt.uri_path = path.split("/")
                if query != "":
                    request_copy.opt.uri_query = query.split("&")
                d = None
                d = self.protocol.request(request_copy, self.observe_callback, block1_callback, block2_callback,
                                          observeCallbackArgs=[card], block1CallbackArgs=[d], block2CallbackArgs=[d])
                pending.append(d)
                d.addBoth(remove_from_pending, d)
                d.addCallback(set_winner)
                d.addErrback(request_failed)

        pending = []
        dns_result_list_exhausted = []
        successful = []
        failures = []
        winner = defer.Deferred(canceller=cancel_request)
        lc = task.LoopingCall(iterate_requests)
        lc.start(0.3)
        return winner

    def process_response(self, response, card):
        card.response = response
        card.response_payload.text = '[b]Code:[/b] ' + coap.responses[card.response.code]
        card.response_payload.text += "\n[b]Type:[/b] " + coap.types[card.response.mtype]
        card.response_payload.text += "\n[b]ID:[/b] " + hex(card.response.mid)
        card.response_payload.text += "\n[b]Token:[/b] 0x" + card.response.token.encode('hex')
        formatted_options = "\n[b]Options:[/b]"
        for option in card.response.opt.option_list():
            formatted_options += "\n- "
            if option.number in coap.options:
                formatted_options += coap.options[option.number]
            else:
                formatted_options += "Unknown"
            formatted_options += " (" + str(option.number) + ")"
            if option.value is not None:
                formatted_options += " : " + str(option.value)
        card.response_payload.text += formatted_options
        card.response_payload.text += '\n\n[b]Response:[/b] ' + card.response.payload

    def observe_callback(self, response, card):
        self.process_response(response, card)

    def print_error(self, failure, card):
        r = failure.trap(InvalidURI, FragmentNotAllowed, socket.gaierror, socket.error, error.RequestTimedOut, defer.CancelledError)
        if r == InvalidURI:
            log.msg("Error: invalid URI")
            card.response_payload.text = "Error: Invalid URI!"
        elif r == FragmentNotAllowed:
            log.msg("Error: fragment found")
            card.response_payload.text = "Error: URI fragment not allowed for CoAP!"
        elif r == socket.gaierror or r == socket.error:
            log.msg("Error: hostname not found")
            card.response_payload.text = "Error: hostname not found!"
        elif r == error.RequestTimedOut:
            log.msg("Error: request timed out")
            card.response_payload.text = 'Error: request timed out!'

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

class GridTabbedPanel(TabbedPanel):

    def __init__(self, **kwargs):
        self.accept_field_values = coap.media_types.values()
        self.accept_field_values.append('none')
        super(GridTabbedPanel, self).__init__(**kwargs)
        self.controller = kwargs.get('controller', None)
        #In next line original TabbedPanelContent object is replaced
        #by custom made TabbedPanelContentGrid object
        self.content = TabbedPanelContentGrid()
        self.content.bind(height=self.update_height)
        self.bind(tab_height=self.update_height)

    def update_height(self, obj, value):
        """This is a setter for height"""
        #This method is necessary because using kv file does not work properly
        self.height = self.content.height + self.tab_height

    def _update_scrollview(self, scrl_v, *l):
        #This method is necessary because in TabbedPanel there
        #is a hidden ScrollView with ugly scroll bars.
        #That line sets scroll bars transparent.
        scrl_v.bar_color = [0,0,0,0]
        super(GridTabbedPanel, self)._update_scrollview(scrl_v, *l)

class MethodPanel(GridTabbedPanel):
    pass

class FlatButton(Button):
    background_normal = ListProperty([.5, .5, .5, .5])
    background_down = ListProperty([1, 1, 1, 1])

class SpinnerButton(SpinnerOption):
    pass

class NodeLabel(Label, TreeViewNode):

    def __init__(self, **kwargs):
        super(NodeLabel, self).__init__(**kwargs)
        self.controller = kwargs.get('controller', None)
        self.identifier = kwargs.get('identifier', None)

    def open_node_label_popup(self, link_node, value):
        if value=='node' and self.level == 1:
            content = BoxLayout(orientation='vertical', spacing=5)
            content.add_widget(PopupButton(text='Repeat discovery',on_release=self.open_link))
            content.add_widget(PopupButton(text='Remove discovery result',on_release=self.remove_node))
            self.controller.popup.content = content
            self.controller.popup.open()
        elif value=='uri':
            content = BoxLayout(orientation='vertical', spacing=5)
            content.add_widget(PopupButton(text='Open bookmark',on_release=self.open_link))
            content.add_widget(PopupButton(text='Remove bookmark',on_release=self.remove_bookmark))
            self.controller.popup.content = content
            self.controller.popup.open()

    def remove_node(self, button):
        self.controller.remove_link_list(self.identifier)
        self.controller.popup.dismiss()

    def remove_bookmark(self, button):
        self.controller.remove_bookmark(self.identifier)
        self.controller.popup.dismiss()

    def open_link(self, button):
        self.controller.choose_bookmark(self.identifier)
        self.controller.popup.dismiss()

class FavouritePanel(GridTabbedPanel):
    pass

class NodesScreen(Screen):

    def __init__(self, **kwargs):
        super(NodesScreen, self).__init__(**kwargs)
        self.screen_manager = kwargs['screen_manager']
        self.discoveries = {}
        self.bookmarks = {}
        self.load_link_list()
        self.popup = Popup(title='Actions',
           content=Label(text=''),
           size_hint=(None, None), size=(400, 400))

    def add_bookmark(self, uri):
        self.remove_bookmark(uri)
        bookmark_txt = '[ref=uri]' + uri + '[/ref]'
        bookmark_node = self.bookmarks_tree.add_node(NodeLabel(text=bookmark_txt, controller=self, identifier=uri))
        bookmark_node.bind(on_ref_press=bookmark_node.open_node_label_popup)
        self.bookmarks[uri] = bookmark_node

    def remove_bookmark(self, uri):
        try:
            bookmark_node = self.bookmarks.pop(uri)
        except KeyError:
            pass
        else:
            self.bookmarks_tree.remove_node(bookmark_node)

    def add_link_list(self, rawdata, identifier):
        self.remove_link_list(identifier)
        source_txt = '[ref=node]' + identifier + '[/ref]'
        source_node = self.tree_view.add_node(NodeLabel(text=source_txt, controller=self, identifier=identifier))
        source_node.bind(on_ref_press=source_node.open_node_label_popup)
        self.discoveries[identifier] = (source_node, rawdata)
        link_list = link_header.parse(rawdata)
        for link in link_list.links:
            link_txt = '[ref=world]' + link.href + '[/ref]'
            link_node = self.tree_view.add_node(NodeLabel(text=link_txt, controller=self), source_node)
            link_node.link = link
            link_node.bind(on_ref_press=self.choose_link)
            for attribute in link.attr_pairs:
                if attribute[1] is not None:
                    attr_txt = "[color=00ffff][b]" + attribute[0] + " = [/b][/color][color=0066ff]" + attribute[1] + "[/color]"
                else:
                    attr_txt = "[color=00ffff][b]" + attribute[0] + "[/b][/color]"
                self.tree_view.add_node(NodeLabel(text=attr_txt, controller=self), link_node)

    def remove_link_list(self, identifier):
        try:
            source_node, rawdata = self.discoveries.pop(identifier)
        except KeyError:
            pass
        else:
            self.tree_view.remove_node(source_node)

    def choose_link(self, link_node, value):
        scheme, netloc, path, query, fragment = urlsplit(link_node.link.href)
        if scheme == "" and netloc == "":
            #relative URI
            if link_node.link.rel is None or link_node.link.rel is "hosts":
                #Using default relation "hosts"
                p_scheme, p_netloc, p_path, p_query, p_fragment = urlsplit(link_node.parent_node.identifier)
                target_uri = urlunsplit((p_scheme, p_netloc, path, query, fragment))
        else:
            target_uri = link_node.link.href
        self.screen_manager.get_screen('controller').address_bar.text = target_uri
        log.msg("Put link %s into browser address box" % target_uri)
        self.open_main_screen()

    def choose_bookmark(self, uri):
        self.screen_manager.get_screen('controller').address_bar.text = uri
        log.msg("Put link %s into browser address box" % uri)
        self.open_main_screen()

    def open_main_screen(self):
        self.screen_manager.transition.direction = 'left'
        self.screen_manager.current = 'controller'

    def save_link_list(self):
        disc = {}
        for key, value in self.discoveries.iteritems():
            source_node, rawdata = value
            disc[key] = rawdata
        bkmark = {}
        for key, value in self.bookmarks.iteritems():
            bkmark[key] = True
        data = (disc, bkmark)
        output = open('link_list.dat', 'wb')
        cPickle.dump(data, output, -1)
        output.close()

    def load_link_list(self):
        try:
            input = open('link_list.dat', 'rb')
            data = cPickle.load(input)
            disc, bkmark = data
        except IOError:
            log.msg("No link_list.dat found.")
        except ValueError:
            log.msg("File link_list.dat incomplete.")
        except cPickle.UnpicklingError:
            log.msg("File link_list.dat bad or corrupt.")
        else:
            for key, value in disc.iteritems():
                self.add_link_list(value, key)
            for key, value in bkmark.iteritems():
                self.add_bookmark(key)

class CoapBrowserApp(App):

    def build(self):
        self.create_protocol()
        sm = ScreenManager(transition=SlideTransition())
        sm.add_widget(MainScreen(name='controller', protocol=self.protocol, screen_manager=sm))
        sm.add_widget(NodesScreen(name='nodes', screen_manager=sm))
        print self.get_application_config()
        return sm

    def create_protocol(self):
        endpoint = resource.Endpoint(None)
        self.protocol = coap.Coap(endpoint)
        reactor.listenUDP(0, self.protocol, interface="::")

    def on_pause(self):
        self.root.get_screen('nodes').save_link_list()
        return True

    def on_resume(self):
        pass

    def on_stop(self):
        self.root.get_screen('nodes').save_link_list()

if __name__ == '__main__':
    log.startLogging(sys.stdout)
    CoapBrowserApp().run()







