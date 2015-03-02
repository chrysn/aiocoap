aiocoap -- The Python CoAP library
==================================

The aiocoap package is a Python implementation of CoAP, the Constrained
Application Protocol (`RFC 7252`_, more info at http://coap.technology/).

It uses the asyncio module introduced in Python 3.4 to facilitate concurrent
operations while maintaining a simple to use interface and not depending on
anything outside the standard library.

aiocoap is originally based on txThings_. If you want to use CoAP in your
existing twisted application, or can not migrate to Python 3 yet, that is
probably more useful to you than aiocoap.

.. _`RFC 7252`: http://tools.ietf.org/html/rfc7252
.. _txThings: https://github.com/siskin/txThings

Usage
-----

For details on how to use the aiocoap library, have a look at the :mod:`aiocoap`
module documentation, or at the :doc:`examples` and :doc:`tools` provided.

All examples can be run directly from a source code copy. If you prefer to
install it, the usual Python mechanisms apply.

Development
-----------

aiocoap tries to stay close to PEP8_ recommendations and general best practice,
and should thus be easy to contribute to. Unit tests are implemented in the
``./tests/`` directory; complete test coverage is aimed for, but not yet
complete (and might never be, as the error handling for pathological network
partners is hard to trigger with a library designed not to misbehave).

Documentation is built using sphinx_; hacks used there are described in
``./doc/README.doc``.

Bugs from design goal and wishlist to typos are currently tracked in github
(see below).

.. _PEP8: http://legacy.python.org/dev/peps/pep-0008/
.. _sphinx: http://sphinx-doc.org/

Relevant URLs
-------------

* https://github.com/chrysn/aiocoap

  This is where the latest source code can be found, and bugs can be reported.
  Generally, this serves as the project web site.

* http://aiocoap.readthedocs.org/

  Online documentation built from the sources.


Licensing
---------

aiocoap is published under the MIT License, see :doc:`LICENSE` for details.

Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
              2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
