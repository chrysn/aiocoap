# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT


from .resource import *
from .util import _Throttler


class KivyPropertyBacked(SenmlResource):
    """Provides a .value bound to the self.widget_property property of the
    self.backend_widget Kivy widget. The widget and widget_property need to be
    set before this class's __init__ is called."""

    def __init__(self):
        super().__init__()
        throttler = _Throttler(self.value_changed)
        self.backend_widget.bind(**{self.widget_property: lambda *args: throttler()})

    def _get_value(self):
        return getattr(self.backend_widget, self.widget_property)

    def _set_value(self, updated):
        setattr(self.backend_widget, self.widget_property, updated)

    value = property(_get_value, _set_value)


class Color(KivyPropertyBacked):
    def __init__(self, kivy_backend, widget_property):
        self.backend_widget = kivy_backend
        self.widget_property = widget_property
        super().__init__()

    @ContenttypeRendered.get_handler("text/plain;charset=utf-8", default=True)
    def __regular_get(self):
        return "#" + "".join("%02x" % int(255 * c) for c in self._get_value()[:3])

    # 65362 is the content format used for SAUL RGB values, also in verdigris (manual clients will just send none)
    #
    # See also https://rustdoc.etonomy.org/riot_coap_handler_demos/saul/index.html
    @ContenttypeRendered.put_handler(65362, default=True)
    def render_put(self, payload):
        if len(payload) == 7 and payload[0:1] == b"#":
            values = tuple(
                int(payload[i : i + 2].decode("ascii"), 16) / 255 for i in (1, 3, 5)
            )
        else:
            return Message(code=BAD_REQUEST)

        self._set_value(values + (1,))

    def get_link_description(self):
        return {"saul": "ACT_LED_RGB", "if": "core.p"}


class Text(StringResource, KivyPropertyBacked):
    """A resource that represents a Kivy widget's text"""

    if_ = "core.p"

    widget_property = "text"

    def __init__(self, kivy_backend):
        self.backend_widget = kivy_backend
        super().__init__()


class PressState(BooleanResource, KivyPropertyBacked):
    """A resource that resesents a Kivy widget's "pressed" property"""

    if_ = "core.s"

    widget_property = "state"

    # This is no good modelling (for a button modelled as press-release is hard
    # to observe with eventually consistent semantics only), but it works for a
    # first demo.

    def __init__(self, kivy_backend):
        self.backend_widget = kivy_backend
        super().__init__()

    # fake boolean, and don't allow setting

    def _get_value(self):
        return {"down": 1, "normal": 0}[super()._get_value()]

    value = property(_get_value)
