import asyncio

from .resource import *
from .util import _Throttler

class KivyPropertyBacked(SenmlResource):
    """Provides a .value bound to the self.widget_property property of the
    self.backend_widget Kivy widget. The widget and widget_property need to be
    set before this class's __init__ is called."""

    def __init__(self):
        super().__init__()
        throttler = _Throttler(self.value_changed)
        asyncio.get_event_loop().create_task(self._monitor(throttler))

    async def _monitor(self, throttler):
        async for evt in self.backend_widget.async_bind(self.widget_property):
            throttler()

    def _get_value(self):
        return getattr(self.backend_widget, self.widget_property)

    def _set_value(self, updated):
        setattr(self.backend_widget, self.widget_property, updated)

    value = property(_get_value, _set_value)

class Text(StringResource, KivyPropertyBacked):
    """A resource that represents a Kivy widget's text"""

    if_ = "core.p"

    widget_property = 'text'

    def __init__(self, kivy_backend):
        self.backend_widget = kivy_backend
        super().__init__()

class PressState(BooleanResource, KivyPropertyBacked):
    """A resource that resesents a Kivy widget's "pressed" property"""

    if_ = "core.s"

    widget_property = 'state'

    # This is no good modelling (for a button modelled as press-release is hard
    # to observe with eventualy consistent semantics only), but it works for a
    # first demo.

    def __init__(self, kivy_backend):
        self.backend_widget = kivy_backend
        super().__init__()

    # fake boolean, and don't allow setting

    def _get_value(self):
        return {'down': 1, 'normal': 0}[super()._get_value()]

    value = property(_get_value)
