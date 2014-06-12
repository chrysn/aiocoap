# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# txThings is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""
aiocoap
=======

The aiocoap package is a library that implements CoAP, the Constrained
Application Protocol (`RFC pending`_).

.. _`RFC pending`: https://datatracker.ietf.org/doc/draft-ietf-core-coap/

Usage
-----

In all but the most exotic applications, you will want to create a single
:class:`aiocoap.protocol.Endpoint` instance that binds to the network.
Depending on whether you are implementing a server or a client, it binds to the
default CoAP port 5683 or to a high port.

With a client, requests get sent by assembling a :class:`iot.message.Message`,
and requesting it to be handled using the :meth:`iot.coap.CoAP.request` method.

With a server, a resource tree gets built from :class:`iot.resource.Resurce`
objects, whose root gets passed to the :class:`iot.coap.CoAP` object on
initialization.
"""

## Using those imports is deprecated. Instead, it is recommended to `from
## aiocoap.numbers import *` and explicitly import what you need from
## everything else.

from .numbers import *
from .message import Message
from .protocol import Endpoint
