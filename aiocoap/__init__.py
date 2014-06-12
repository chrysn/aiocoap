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
:class:`.Endpoint` instance that binds to the network. The
:meth:`.Endpoint.create_client_endpoint` and
:meth:`.Endpoint.create_server_endpoint` coroutines give you a readily connected
endpoint.

On the client side, you can request resources by assembling a
:class:`.Message` and passing it to your endpoint's
:meth:`.Endpoint.request` coroutine, which returns the response message.

On the server side, a resource tree gets built from
:class:`aiocoap.resource.CoAPResource` objects into a
:class:`aiocoap.resource.Site`, which is assigned to the endpoint at creation
time.
"""

from .numbers import *
from .message import Message
from .protocol import Endpoint
