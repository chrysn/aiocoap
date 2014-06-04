# This file is part of the txThings project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# txThings is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""
txThings
========

The txThings package is a library that implements CoAP, the Constrained
Application Protocol (`RFC pending`_). The current implementation is not based
on twisted but on Python 3.4's asyncio module. (This is the asyncio branch of
txThings).

.. _`RFC pending`: https://datatracker.ietf.org/doc/draft-ietf-core-coap/

Usage
-----

In all but the most exotic applications, you will want to create a single
:class:`iot.coap.CoAP` instance that binds to the network. Depending on whether
you are implementing a server or a client, it binds to the default CoAP port
5683 or to a high port.

With a client, requests get sent by assembling a :class:`iot.message.Message`,
and requesting it to be handled using the :meth:`iot.coap.CoAP.request` method.

With a server, a resource tree gets built from :class:`iot.resource.Resurce`
objects, whose root gets passed to the :class:`iot.coap.CoAP` object on
initialization.
"""
