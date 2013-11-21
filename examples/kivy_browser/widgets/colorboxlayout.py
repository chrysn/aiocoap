from kivy.uix.gridlayout import GridLayout
from kivy.properties import OptionProperty, StringProperty, ListProperty, ObjectProperty

class ColorBoxLayout(GridLayout):

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

    color = ListProperty([1, 1, 1, 1])
    '''Text color, in the format (r, g, b, a)

    :data:`color` is a :class:`~kivy.properties.ListProperty`, default to [1, 1,
    1, 1].
    '''

    texture = ObjectProperty(None, allownone=True)
    '''Texture object of the text.
    The text is rendered automatically when a property changes. The OpenGL
    texture created in this operation is stored in this property. You can use
    this :data:`texture` for any graphics elements.

    Depending on the texture creation, the value will be a
    :class:`~kivy.graphics.texture.Texture` or
    :class:`~kivy.graphics.texture.TextureRegion` object.

    .. warning::

        The :data:`texture` update is scheduled for the next frame. If you need
        the texture immediately after changing a property, you have to call
        the :meth:`texture_update` method before accessing :data:`texture`::

            l = Label(text='Hello world')
            # l.texture is good
            l.font_size = '50sp'
            # l.texture is not updated yet
            l.texture_update()
            # l.texture is good now.

    :data:`texture` is a :class:`~kivy.properties.ObjectProperty`, default to
    None.
    '''

    texture_size = ListProperty([0, 0])
    '''Texture size of the text.

    .. warning::

        The :data:`texture_size` is set after the :data:`texture` property. If
        you listen for changes to :data:`texture`, :data:`texture_size` will not
        be up-to-date in your callback. Bind to :data:`texture_size` instead.
    '''