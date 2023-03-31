# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

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

import numbers
# flake8 doesn't see through the global re-export
from .numbers import * # noqa: F401, F403
from .message import Message, NoResponse
from .protocol import Context

__all__ = numbers.__all__ + ['Message', 'NoResponse', 'Context']
