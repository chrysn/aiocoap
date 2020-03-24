aiocoap -- The Python CoAP library
==================================

The aiocoap package is an implementation of CoAP, the `Constrained Application
Protocol`_.

It is written in Python 3 using its `native asyncio`_ methods to facilitate
concurrent operations while maintaining an easy to use interface.

aiocoap is originally based on txThings_. If you want to use CoAP in your
existing Twisted application, or can not migrate to Python 3 yet, that is
probably more useful to you than aiocoap.

.. _`Constrained Application Protocol`: http://coap.technology/
.. _`native asyncio`: https://docs.python.org/3/library/asyncio
.. _txThings: https://github.com/siskin/txThings

Usage
-----

For how to use the aiocoap library, have a look at the guidedtour_, or at
the examples_ and tools_ provided.

A full reference is available in the  `API documentation`_.

All examples can be run directly from a source code copy. If you prefer to
install it, the usual Python mechanisms apply (see installation_).

.. _`API documentation`: http://aiocoap.readthedocs.io/en/latest/api.html

Features / Standards
--------------------

This library supports the following standards in full or partially:

* RFC7252_ (CoAP): missing are a caching and cross proxy implementation, proper
  multicast (support is incomplete); DTLS support is client-side only so far,
  and lacking some security properties.
* RFC7641_ (Observe): Reordering, re-registration, and active cancellation are
  missing.
* RFC7959_ (Blockwise): Multicast exceptions missing.
* RFC8323_ (TCP): Supports CoAP over TCP and TLS (certificate only, no
  preshared or raw public keys) but not CoAP over WebSockets.
* RFC7967_ (No-Response): Supported.
* RFC8132_ (PATCH/FETCH): Types and codes known, FETCH observation supported
* draft-ietf-core-resource-directory_: A standalone resource directory
  server is provided along with a library function to register at one. They
  lack support for groups and security considerations, and are generally rather
  simplistic.
* RFC8613_ (OSCORE): Full support client-side; protected servers can be
  implemented based on it but are not automatic yet.

If something described by one of the standards but not implemented, it is
considered a bug; please file at the `github issue tracker`_. (If it's not on
the list or in the excluded items, file a wishlist item at the same location).

.. _RFC7252: https://tools.ietf.org/html/rfc7252
.. _RFC7641: https://tools.ietf.org/html/rfc7641
.. _RFC7959: https://tools.ietf.org/html/rfc7959
.. _RFC7967: https://tools.ietf.org/html/rfc7967
.. _RFC8132: https://tools.ietf.org/html/rfc8132
.. _RFC8323: https://tools.ietf.org/html/rfc8323
.. _RFC8613: https://tools.ietf.org/html/rfc8613
.. _draft-ietf-core-resource-directory: https://tools.ietf.org/html/draft-ietf-core-resource-directory-14

Dependencies
------------

Basic aiocoap works out of the box on Python_ 3.5.2 or newer (also works on
PyPy3_). For full support (DTLS, OSCORE and link-format handling) follow the
installation_ instructions as these require additional libraries.

aiocoap provides different network backends for different platforms. The
udp6_ module is most full-featured, but ties into the default asyncio loop
and requires full POSIX network interfaces only available on Linux and possibly
some BSDs. On Windows and macOS, more constrained server_ and client_
transports with some caveats of their own are used; for more details, see the
currently open `platform issues`_. Alternative main loops like uvloop_ or
gbulb_ can be used without restriction.

If your library depends on aiocoap, it should pick the required extras (as per
installation_) and declare a dependency like ``aiocoap[linkheader,oscore] >= 0.4b2``.

.. _Python: https://www.python.org/
.. _PyPy3: http://pypy.org/
.. _udp6: http://aiocoap.readthedocs.io/en/latest/module/aiocoap.transports.udp6.html
.. _uvloop: https://uvloop.readthedocs.io/
.. _gbulb: https://github.com/nathan-hoad/gbulb
.. _`platform issues`: https://github.com/chrysn/aiocoap/issues?q=is%3Aissue+is%3Aopen+label%3A%22platform+support%22
.. _server: http://aiocoap.readthedocs.io/en/latest/module/aiocoap.transports.simplesocketserver.html
.. _client: http://aiocoap.readthedocs.io/en/latest/module/aiocoap.transports.simple6.html

Development
-----------

aiocoap tries to stay close to PEP8_ recommendations and general best practice,
and should thus be easy to contribute to.

Bugs (ranging from "design goal" and "wishlist" to typos) are currently tracked
in the `github issue tracker`_. Pull requests are welcome there; if you start
working on larger changes, please coordinate on the issue tracker.

Documentation is built using sphinx_ with ``./setup.py build_sphinx``; hacks
used there are described in ``./doc/README.doc``.

Unit tests are implemented in the ``./tests/`` directory and easiest run using
``./setup.py test``; complete test coverage is aimed for, but not yet complete
(and might never be, as the error handling for pathological network partners is
hard to trigger with a library designed not to misbehave). The tests are
regularly run at the `CI suite at gitlab`_, from where `coverage reports`_ are
available.

.. _PEP8: http://legacy.python.org/dev/peps/pep-0008/
.. _sphinx: http://sphinx-doc.org/
.. _`github issue tracker`: https://github.com/chrysn/aiocoap/issues
.. _`CI suite at gitlab`: https://gitlab.com/aiocoap/aiocoap/commits/master
.. _`coverage reports`: https://aiocoap.gitlab.io/aiocoap/

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
.. _`aiocoap module`: http://aiocoap.readthedocs.io/en/latest/module/aiocoap.html
.. _LICENSE: LICENSE
