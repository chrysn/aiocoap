The aiocoap API
===============

This is about the Python API of the aiocoap library;
see :doc:`design` for notes on how CoAP concepts play into the API.

API stability
-------------

In preparation for a `semantically versioned`_ 1.0 release, some parts of
aiocoap are described as stable.

The library does not try to map the distinction between "public API" and
internal components in the sense of semantic versioning to Python's "public"
and "private" (``_``-prefixed) interaces -- tying those together would mean
intrusive refactoring every time a previously internal mechanism is stabilized.

Neither does it only document the public API, as that would mean that library
development would need to resort to working with code comments; that would also
impede experimentation, and migrating comments to docstrings would be intrusive
again. All modules' documentation can be searched, and most modules are listed
below.

Instead, functions, methods and properties in the library should only be
considered public (in the semantic versioning sense) if they are described as
"stable" in their documentation. The documentation may limit how an interface
may used or what can be expected from it. (For example, while a method may be
typed to return a particular class, the stable API may only guarantee that an
instance of a particular abstract base class is returned).


The ``__all__`` attributes of aiocoap modules try to represent semantic
publicality of its members (in accordance with PEP8); however, the
documentation is the authoritative source.

Modules with stable components
------------------------------

.. toctree::
   :titlesonly:

   module/aiocoap
   module/aiocoap.protocol
   module/aiocoap.message
   module/aiocoap.options
   module/aiocoap.interfaces
   module/aiocoap.error
   module/aiocoap.pipe

   module/aiocoap.defaults
   module/aiocoap.transports
   module/aiocoap.proxy
   module/aiocoap.proxy.client
   module/aiocoap.proxy.server
   module/aiocoap.numbers
   module/aiocoap.optiontypes
   module/aiocoap.resource
   module/aiocoap.util
   module/aiocoap.cli
   module/aiocoap.meta

   module/aiocoap.oscore

.. _`semantically versioned`: https://semver.org/
