'''
Created on 14-09-2013

@author: Maciej Wasilak

This is a Kivy widget class used to display a "browsing card" - a rectangle
that contains browsing result. Card can be closed with a swipe to the right.
It should be used on touch screens.

Caution: this class is experimental and may contain bugs!!!
'''

from kivy.uix.gridlayout import GridLayout
from kivy.uix.relativelayout import RelativeLayout
from functools import partial
from kivy.animation import Animation
from kivy.clock import Clock
from kivy.properties import BooleanProperty, OptionProperty, AliasProperty, \
                            NumericProperty, ListProperty, ObjectProperty,\
                            StringProperty


class BrowsingCard(GridLayout):

    min_move = NumericProperty(0.2)
    anim_move_duration = NumericProperty(0.5)
    anim_cancel_duration = NumericProperty(0.3)
    scroll_timeout = NumericProperty(150)
    scroll_distance = NumericProperty('20dp')


    _current = ObjectProperty(None, allownone=True)
    _offset = NumericProperty(0)
    _touch = ObjectProperty(None, allownone=True)

    def __init__(self, **kwargs):
        super(BrowsingCard, self).__init__(**kwargs)
        self.controller = kwargs['controller']
        self._trigger_position_visible_slides = Clock.create_trigger(
                self._position_visible_slides, -1)

    def add_widget(self, widget, index=0):
        slide = RelativeLayout(size=self.size, x=self.x, y=self.y)
        slide.add_widget(widget)
        super(BrowsingCard, self).add_widget(slide, index)
        self.slide = widget
        self.slide.bind(height=self._update_height)

    def _update_height(self, instance, value):
        self.height = instance.height

    def remove_widget(self, widget, *args, **kwargs):
        return super(BrowsingCard, self).remove_widget(widget, *args, **kwargs)

    def _position_visible_slides(self, *args):
        slide = self.slide
        if not slide:
            return
        x = self.x
        _offset = self._offset
        xoff = x + _offset
        slide.pos = (xoff, 0)

    def on__offset(self, *args):
        self._trigger_position_visible_slides()

    def on_pos(self, *args):
        self._trigger_position_visible_slides()

    def _start_animation(self, *args):
        Animation.cancel_all(self)
        new_offset = 0
        extent = self.width
        #if self._offset < self.min_move * -extent:
        #    new_offset = -extent
        if self._offset > self.min_move * extent:
            new_offset = extent

        dur = self.anim_move_duration
        if new_offset == 0:
            dur = self.anim_cancel_duration

        anim = Animation(_offset=new_offset, d=dur, t='out_quad')
        if new_offset == extent:
            anim.bind(on_complete=self.controller.close_card)
        anim.start(self)



    def _get_uid(self, prefix='sv'):
        return '{0}.{1}'.format(prefix, self.uid)

    def on_touch_down(self, touch):
        if not self.collide_point(*touch.pos):
            touch.ud[self._get_uid('cavoid')] = True
            return
        if self._touch:
            return super(BrowsingCard, self).on_touch_down(touch)
        Animation.cancel_all(self)
        self._touch = touch
        uid = self._get_uid()
        touch.grab(self)
        touch.ud[uid] = {
            'mode': 'unknown',
            'time': touch.time_start}
        Clock.schedule_once(self._change_touch_mode,
                self.scroll_timeout / 1000.)
        return True

    def on_touch_move(self, touch):
        if self._get_uid('cavoid') in touch.ud:
            return
        if self._touch is not touch:
            super(BrowsingCard, self).on_touch_move(touch)
            return self._get_uid() in touch.ud
        if touch.grab_current is not self:
            return True
        ud = touch.ud[self._get_uid()]
        if ud['mode'] == 'unknown':
            distance = abs(touch.ox - touch.x)
            if distance > self.scroll_distance:
                Clock.unschedule(self._change_touch_mode)
                ud['mode'] = 'scroll'
        else:
            self._offset += touch.dx
        return True

    def on_touch_up(self, touch):
        if self._get_uid('cavoid') in touch.ud:
            return
        if self in [x() for x in touch.grab_list]:
            touch.ungrab(self)
            self._touch = None
            ud = touch.ud[self._get_uid()]
            if ud['mode'] == 'unknown':
                Clock.unschedule(self._change_touch_mode)
                super(BrowsingCard, self).on_touch_down(touch)
                Clock.schedule_once(partial(self._do_touch_up, touch), .1)
            else:
                self._start_animation()
        else:
            if self._touch is not touch and self.uid not in touch.ud:
                super(BrowsingCard, self).on_touch_up(touch)
        return self._get_uid() in touch.ud

    def _do_touch_up(self, touch, *largs):
        super(BrowsingCard, self).on_touch_up(touch)
        # don't forget about grab event!
        for x in touch.grab_list[:]:
            touch.grab_list.remove(x)
            x = x()
            if not x:
                continue
            touch.grab_current = x
            super(BrowsingCard, self).on_touch_up(touch)
        touch.grab_current = None

    def _change_touch_mode(self, *largs):
        if not self._touch:
            return
        self._start_animation()
        uid = self._get_uid()
        touch = self._touch
        ud = touch.ud[uid]
        if ud['mode'] == 'unknown':
            touch.ungrab(self)
            self._touch = None
            touch.push()
            touch.apply_transform_2d(self.to_widget)
            touch.apply_transform_2d(self.to_parent)
            super(BrowsingCard, self).on_touch_down(touch)
            touch.pop()
            return
