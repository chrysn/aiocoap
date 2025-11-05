.. meta::
  :copyright: SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
  :copyright: SPDX-License-Identifier: MIT

|documentation| |git sources on codeberg| |on PyPI| |CI status| |coverage report| |following OpenSSF Best Practices|


aiocoap – The Python CoAP library
=================================

The aiocoap package is an implementation of CoAP, the `Constrained Application
Protocol`_. It facilitates writing applications that talk to
network enabled embedded ("IoT" / "Internet of Things") devices.

It is written in Python 3 using its `native asyncio`_ methods to facilitate
concurrent operations while maintaining an easy to use interface.

.. _`Constrained Application Protocol`: http://coap.space/
.. _`native asyncio`: https://docs.python.org/3/library/asyncio

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

* RFC7252_ (CoAP): Supported for clients and servers. Multicast is supported on
  the server side, and partially for clients. DTLS is supported but experimental,
  and lacking some security properties. No caching is done inside the library.
* RFC7641_ (Observe): Basic support for clients and servers. Reordering,
  re-registration, and active cancellation are missing.
* RFC7959_ (Blockwise): Supported both for atomic and random access.
* RFC8323_ (TCP, WebSockets): Supports CoAP over TCP, TLS, and WebSockets (both
  over HTTP and HTTPS). The TLS parts are server-certificate only;
  preshared, raw public keys and client certificates are not supported yet.
* RFC7967_ (No-Response): Supported.
* RFC8132_ (PATCH/FETCH): Types and codes known, FETCH observation supported.
* RFC9176_: A standalone resource directory
  server is provided along with a library function to register at one. They
  lack support for groups and security considerations, and are generally rather
  simplistic.
* RFC8613_ (OSCORE): Full support client-side; protected servers can be
  implemented based on it but are not automatic yet.
* draft-ietf-core-oscore-groupcomm-23_ (Group OSCORE): Supported for both group
  and pairwise mode in groups that are fully known. (The lack of an implemented
  joining or persistence mechanism makes this impractical for anything but
  experimentation.)
* RFC9528_ (EDHOC): Experimental and rudimentary support for configured peers
  using the lakers_ implementation.

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
.. _RFC9176: https://tools.ietf.org/html/rfc9176
.. _RFC9528: https://tools.ietf.org/html/rfc9528
.. _draft-ietf-core-oscore-groupcomm-23: https://tools.ietf.org/html/draft-ietf-core-oscore-groupcomm-23
.. _lakers: https://pypi.org/project/lakers-python/

Dependencies
------------

Basic aiocoap works out of the box on Python_ 3.11 or newer (also works on
PyPy3_). For full support (eg. DTLS, OSCORE and pretty-printing) follow the
installation_ instructions as these require additional libraries.

aiocoap provides different network backends for different platforms. The most
featureful backend is available for Linux, but most operations work on BSDs,
Windows and macOS as well. See the FAQ_ for more details.

If your library depends on aiocoap, it should pick the required extras (as per
installation_) and declare a dependency like ``aiocoap[linkheader,oscore] >= 0.4b2``.

.. _Python: https://www.python.org/
.. _PyPy3: http://pypy.org/
.. _FAQ: http://aiocoap.readthedocs.io/en/latest/faq.html

Development
-----------

aiocoap tries to stay close to PEP8_ recommendations and general best practice,
and should thus be easy to contribute to.

Bugs (ranging from "design goal" and "wishlist" to typos) are currently tracked
in the `github issue tracker`_. Pull requests are welcome there; if you start
working on larger changes, please coordinate on the issue tracker.

Security critical bugs may instead be reported in private to <chrysn@fsfe.org>
(`PGP key`_) for coordinated disclosure; the maintainer reserves the right to
publish fixes ahead of a planned embargo time as he deems suitable.

Documentation is built using sphinx_ with ``python3 -m sphinx doc/ ${TARGET}``;
hacks used there are described in ``./doc/README.doc``.

Unit tests are implemented in the ``./tests/`` directory and easiest run using
tox_ (but also available through ``python3 -m unittest`` to test the local environment);
complete test coverage is aimed for, but not yet complete (and might never be,
as the error handling for pathological network partners is hard to trigger with
a library designed not to misbehave). The tests are regularly run at the `CI
suite at codeberg`_, from where `coverage reports`_ are available.

.. _PEP8: http://legacy.python.org/dev/peps/pep-0008/
.. _sphinx: http://sphinx-doc.org/
.. _`github issue tracker`: https://github.com/chrysn/aiocoap/issues
.. _`CI suite at codeberg`: https://ci.codeberg.org/repos/12879
.. _`coverage reports`: https://aiocoap.codeberg.page/aiocoap/coverage/
.. _tox: https://tox.readthedocs.io/
.. _`PGP key`: https://christian.amsuess.com/pgp

Relevant URLs
-------------

* https://codeberg.org/aiocoap/aiocoap

  This is where the latest source code can be found.
  Generally, this serves as the project web site.

* http://aiocoap.readthedocs.org/

  Online documentation built from the sources.

* https://coap.space/

  Further general information on CoAP, the standard documents involved, and
  other implementations and tools available.

Licensing
---------

aiocoap is published under the MIT License, and follows the best practice of `reuse.software`_.
Files in ``aiocoap/util/vendored/`` may have different (but compatible and OSI approved) licenses.

When using aiocoap for a publication, please cite it according to `CITATION.cff`_.

Copyright Christian Amsüss and the aiocoap contributors.

aiocoap was originally based on txThings_ by Maciej Wasilak.
The full list of aiocoap contributors can be obtained from the version control history.

.. Any filtering by a mailmap would apply, but no need to state that unless we do get a mailmap.

.. Links:

.. _guidedtour: http://aiocoap.readthedocs.io/en/latest/guidedtour.html
.. _examples: http://aiocoap.readthedocs.io/en/latest/examples.html
.. _tools: http://aiocoap.readthedocs.io/en/latest/tools.html
.. _installation: http://aiocoap.readthedocs.io/en/latest/installation.html
.. _reuse.software: https://reuse.software/
.. _txThings: https://github.com/siskin/txThings
.. _`CITATION.cff`: https://codeberg.org/aiocoap/aiocoap/src/branch/main/CITATION.cff

.. Badges:

.. |documentation| image:: https://app.readthedocs.org/projects/aiocoap/badge/?version=latest
   :target: https://aiocoap.readthedocs.io/

.. |git sources on codeberg| image:: https://badgen.net/static/git/on%20codeberg
   :target: https://codeberg.org/aiocoap/aiocoap/

.. |on PyPI| image:: https://badgen.net/pypi/v/aiocoap
   :target: https://pypi.org/project/aiocoap/

.. The "?" at the end keeps the HTML renderer from recognizing it as an SVG, in
   which case it'd turn it into an <object>, which doesn't work on that site
   because of X-Frame-Options sent there.

.. |CI status| image:: https://ci.codeberg.org/api/badges/12879/status.svg?
   :target: https://ci.codeberg.org/repos/12879

.. |coverage report| image:: https://aiocoap.codeberg.page/aiocoap/badges/coverage.svg?
   :target: https://aiocoap.codeberg.page/aiocoap/coverage/

.. |following OpenSSF Best Practices| image:: https://www.bestpractices.dev/projects/10010/badge
   :target: https://www.bestpractices.dev/en/projects/10010
