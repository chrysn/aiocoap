# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""
The aiocoap package is a library that implements CoAP, the `Constrained
Application Protocol`_.

If you are reading this through the Python documentation, be aware that there
is additional documentation available online_ and in the source code's ``doc``
directory.

.. _`Constrained Application Protocol`: http://coap.technology/
.. _online: http://aiocoap.readthedocs.io/

Module contents
---------------

This root module re-exports the most commonly used classes in aiocoap:
:class:`.Context`, :class:`.Message` as well as all commonly used numeric
constants from :mod:`.numbers`; see their respective documentation entries.

The presence of :class:`.Message` and :class:`.Context` in the root module is
stable.
"""

from .numbers import *
from .message import Message, NoResponse
from .protocol import Context
