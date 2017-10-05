# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""
aiocoap
=======

The aiocoap package is a library that implements CoAP, the Constrained
Application Protocol (`RFC 7252`_, more info at http://coap.technology/).

.. _`RFC 7252`: http://tools.ietf.org/html/rfc7252

Usage
-----

In all but the most exotic applications, you will want to create a single
:class:`.Context` instance that binds to the network. The
:meth:`.Context.create_client_context` and
:meth:`.Context.create_server_context` coroutines give you a readily connected
context.

On the client side, you can request resources by assembling a :class:`.Message`
and passing it to your context's :meth:`.Context.request` method, which
returns a :class:`.protocol.Request` object with a
:attr:`.protocol.Request.response` future (which is a :class:`.Message` again).

On the server side, a resource tree gets built from
:class:`aiocoap.resource.Resource` objects into a
:class:`aiocoap.resource.Site`, which is assigned to the context at creation
time.
"""

from .numbers import *
from .message import Message, NoResponse
from .protocol import Context
