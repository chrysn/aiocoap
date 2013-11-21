from kivy.uix.label import Label
from kivy.properties import OptionProperty, StringProperty, ListProperty

class ColorLabel(Label):
    
    background_color = ListProperty([1, 1, 1, 1])
    '''Background color, in the format (r, g, b, a).

    .. versionadded:: 1.0.8

    :data:`background_color` is a :class:`~kivy.properties.ListProperty`,
    default to [1, 1, 1, 1].
    '''

    background_normal = StringProperty(
        'atlas://data/images/defaulttheme/button')
    '''Background image of the button used for default graphical representation,
    when the button is not pressed.

    .. versionadded:: 1.0.4

    :data:`background_normal` is an :class:`~kivy.properties.StringProperty`,
    default to 'atlas://data/images/defaulttheme/button'
    '''

    border = ListProperty([16, 16, 16, 16])
    '''Border used for :class:`~kivy.graphics.vertex_instructions.BorderImage`
    graphics instruction. Used with :data:`background_normal` and
    :data:`background_down`. Can be used for a custom background.

    It must be a list of four values: (top, right, bottom, left). Read the
    BorderImage instruction for more information about how to use it.

    :data:`border` is a :class:`~kivy.properties.ListProperty`, default to (16,
    16, 16, 16)
    '''