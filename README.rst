aiocoap -- The Python CoAP library
==================================

The aiocoap package is a Python implementation of CoAP, the Constrained
Application Protocl (`RFC pending`_).

It uses the asyncio module introduced in Python 3.4 to facilitate concurrent
operations while maintaining a simple to use interface and not depending on
anything outside the standard library.

aiocoap is originally based on txThings_. If you want to use CoAP in your
existing twisted application, or can not migrate to Python 3 yet, that is
probably more useful to you than aiocoap.

.. _`RFC pending`: https://datatracker.ietf.org/doc/draft-ietf-core-coap/
.. _txThings: https://github.com/siskin/txThings

Usage
-----

For details on how to usethe aiocoap library, have a look at the :mod:`aiocoap`
module documentation, or at the :doc:`examples` provided.

Relevant URLs
-------------

* https://github.com/chrysn/aiocoap -- this is where the latest source code can be found
* http://aiocoap.readthedocs.org/ -- online documentation


Licensing
---------

aiocoap is published under the MIT License, see :doc:`LICENSE` for details.

Copyright (c) 2012-214 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
              2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
