aiocoap -- The Python CoAP library
==================================

The aiocoap package is a Python implementation of CoAP, the Constrained
Application Protocol (`RFC 7252`_, more info at http://coap.technology/).

It uses the Python 3's asynchronous I/O to facilitate concurrent operations
while maintaining a simple to use interface and not depending on anything
outside the standard library.

aiocoap is originally based on txThings_. If you want to use CoAP in your
existing twisted application, or can not migrate to Python 3 yet, that is
probably more useful to you than aiocoap.

.. _`RFC 7252`: http://tools.ietf.org/html/rfc7252
.. _txThings: https://github.com/siskin/txThings

Usage
-----

For how to use the aiocoap library, have a look at the guidedtour_, or at
the examples_ and tools_ provided. All the details are in the
`aiocoap module`_ documentation.

All examples can be run directly from a source code copy. If you prefer to
install it, the usual Python mechanisms apply (see installation_).

Features / Standards
--------------------

This library supports the following standards in full or partially:

* RFC7252_ (CoAP): missing are a caching and cross proxy implementation, proper
  multicast (support is incomplete), and DTLS.
* RFC7641_ (Observe): Reordering, re-registration, and active cancellation are
  missing.
* RFC7959_ (Blockwise): Multicast exceptions missing.
* draft-ietf-core-etch-04_: Only registry entries added, but that should be all
  that's neede on the library side.
* draft-ietf-core-resource-directory-10_: A standalone resource directory
  server is provided. It lacks support for groups, PATCHes to endpoint
  locations and security considerations, and is generally rather experimental.
* draft-ietf-core-object-security-02_ (OSCOAP): Infrastructure for supporting
  it is in place (lacking observe and inner-blockwise support), but no simple
  way exists yet for launching protected servers or requests yet.

If something described by one of the standards but not implemented, it is
considered a bug; please file at the `github issue tracker`_. (If it's not on
the list or in the excluded items, file a wishlist item at the same location).

.. _RFC7252: https://tools.ietf.org/html/rfc7252
.. _RFC7641: https://tools.ietf.org/html/rfc7641
.. _RFC7959: https://tools.ietf.org/html/rfc7959
.. _draft-ietf-core-etch-04: https://tools.ietf.org/html/draft-ietf-core-etch-04
.. _draft-ietf-core-resource-directory-10: https://tools.ietf.org/html/draft-ietf-core-resource-directory-10
.. _draft-ietf-core-object-security-02: https://tools.ietf.org/html/draft-ietf-core-object-security-02

Dependencies
------------

Basic aiocoap works out of the box on Python_ 3.4 or greater.

The examples_ require Python 3.5 as they use newer syntax.

Some components (eg. servers that should auto-generate ``.well-known/core``
resources, OSCOAP) require additional packages to be present (eg. the
`link_header`_ module or Python 3.6's backported secrets module); those are
reflected in "extras" dependencies, see ``setup.py`` for details. Python
modules that require all features should declare a dependency on
``aiocoap[all]``.

.. _Python: https://www.python.org/
.. _asyncio: https://pypi.python.org/pypi/asyncio
.. _`RFC 6690`: http://tools.ietf.org/html/rfc6690
.. _`link_header`: https://pypi.python.org/pypi/LinkHeader

Development
-----------

aiocoap tries to stay close to PEP8_ recommendations and general best practice,
and should thus be easy to contribute to. Unit tests are implemented in the
``./tests/`` directory and easiest run using ``./setup.py test``; complete test
coverage is aimed for, but not yet complete (and might never be, as the error
handling for pathological network partners is hard to trigger with a library
designed not to misbehave).

Documentation is built using sphinx_ with ``./setup.py build_sphinx``; hacks
used there are described in ``./doc/README.doc``.

Bugs (ranging from "design goal" and "wishlist" to typos) are currently tracked
in the `github issue tracker`_.

.. _PEP8: http://legacy.python.org/dev/peps/pep-0008/
.. _sphinx: http://sphinx-doc.org/
.. _`github issue tracker`: https://github.com/chrysn/aiocoap/issues

Relevant URLs
-------------

* https://github.com/chrysn/aiocoap

  This is where the latest source code can be found, and bugs can be reported.
  Generally, this serves as the project web site.

* http://aiocoap.readthedocs.org/

  Online documentation built from the sources.

* http://coap.technology/

  Further general information on CoAP, the standard documents involved, and
  other implementations and tools available.

Licensing
---------

aiocoap is published under the MIT License, see LICENSE_ for details.

When using aiocoap for a publication, please cite it according to the output of
``./setup.py cite [--bibtex]``.

Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
              2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>


.. _guidedtour: http://aiocoap.readthedocs.io/en/latest/guidedtour.html
.. _examples: http://aiocoap.readthedocs.io/en/latest/examples.html
.. _tools: http://aiocoap.readthedocs.io/en/latest/tools.html
.. _installation: http://aiocoap.readthedocs.io/en/latest/installation.html
.. _`aiocoap module`: http://aiocoap.readthedocs.io/en/latest/aiocoap.html
.. _LICENSE: LICENSE
