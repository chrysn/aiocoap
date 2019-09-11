from gi.repository import Gtk
from gi.repository import Gdk

from aiocoap import resource
from aiocoap import Message, BAD_REQUEST

from .resource import *
from .util import _Throttler

class GobjectBacked(SenmlResource):
    """Provides a .value bound to the self.widget_property property of the
    self.backend_widget Gobject. The widget and widget_property need to be set
    before this class's __init__ is called."""

    def __init__(self):
        super().__init__()
        throttler = _Throttler(self.value_changed)
        self.backend_widget.connect('notify::' + self.widget_property, lambda *k: throttler())

    def _get_value(self):
        return self.backend_widget.get_property(self.widget_property)

    def _set_value(self, updated):
        self.backend_widget.set_property(self.widget_property, updated)

    value = property(_get_value, _set_value)

class Switch(BooleanResource, GobjectBacked):
    if_ = 'core.s'
    # FIXME export as read-only

    widget_property = 'state'

    def __init__(self, args):
        self.widget = self.backend_widget = Gtk.Switch()
        super().__init__()

class Bulb(BooleanResource):
    if_ = 'core.a'
    # FIXME export as write-only

    def _get_value(self):
        #raise RuntimeError("This object is not readable") # this was a nice idea for a demo, but precludes even toggling
        return self.widget.props.icon_name == 'weather-clear'

    def _set_value(self, new_state):
        self.widget.props.icon_name = {
                True: 'weather-clear',
                False: 'weather-clear-night',
                }[new_state]

    value = property(_get_value, _set_value)

    def __init__(self, args):
        super().__init__()
        self.widget = Gtk.Image()

    @ContenttypeRendered.empty_post_handler()
    def emptypost(self):
        self.value = not self.value

class RGBChannel(FloatResource, PythonBacked):
    if_ = 'core.a'

    channel_name = property(lambda self: ('r', 'g', 'b')[self.channel])

    def __init__(self, channel):
        super().__init__()

        self.channel = channel
        self.value = 0 # FIXME this doesn't cater for notifications

class RGBRoot(SubsiteBatch):
    @ContenttypeRendered.get_handler('text/plain;charset=utf-8', default=True)
    def __regular_get(self):
        return '#' + "".join("%02x"%int(255 * c.value) for c in self.site.channels)

    @ContenttypeRendered.put_handler('text/plain;charset=utf-8', default=True)
    def render_put(self, payload):
        if len(payload) == 7 and payload[0:1] == b'#':
            values = tuple(int(payload[i:i+2].decode('ascii'), 16)/255 for i in (1, 3, 5))
        else:
            return Message(code=BAD_REQUEST)

        # FIXME it'd be nice to update them in a way so that our own
        # value_changed only fires once
        for i, v in enumerate(values):
            self.site.channels[i].value = v

class RGBLight(resource.Site):
    def __init__(self, args):
        super().__init__()

        self.channels = [RGBChannel(i) for i in range(3)]

        for c in self.channels:
            self.add_resource([c.channel_name], c)
        rgbroot = RGBRoot(self)
        self.add_resource([], RGBRoot(self))

        rgbroot.add_valuechange_callback(self.trigger_repaint)

        self.widget = Gtk.DrawingArea()
        self.widget.set_size_request(200, 100)
        self.widget.connect('draw', self.cb_draw)

    def cb_draw(self, widget, cr):
        Gdk.cairo_set_source_rgba(cr, Gdk.RGBA(self.channels[0].value, self.channels[1].value, self.channels[2].value))
        cr.paint()

    def trigger_repaint(self):
        # this is assuming that GtkPaintable doesn't have its own window, which
        # seems not to have been the case for quite some time
        self.widget.queue_draw_area(0, 0, self.widget.get_allocated_width(), self.widget.get_allocated_height())
