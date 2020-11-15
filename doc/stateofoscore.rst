OSCORE in aiocoap
=================

Introducing OSCORE
------------------

OSCORE (RFC8613_) is an end-to-end security mechanism available for CoAP and
implemented in aiocoap.

Its main advantage over lower-layer protection (IPsec, (D)TLS) is that it can
leverage any CoAP transport (as well as HTTP), can traverse proxies preserving
some of their features (like block-wise fragmentation and retransmission) and
supports multicast and other group communication scenarios (implemented, but
not covered here as it needs even more manual actions so far).

By itself, OSCORE has no key exchange protocol; it relies on other protocols to
establidsh keys (there is ongoing work on a lightweight key exchange named
EDHOC, and the ACE-OSCORE_ profile goes some way). Until those are implemented
and wide-spread, OSCORE contexts can be provisioned manually to devices.

OSCORE state
------------

Unless an add-on mode (sometimes called B2 mode as it's describe in OSCORE's
Appendix B.2_) is used, some run-time information needs to be stored along with
an OSCORE key.

This allows instantaneous zero-round-trip trusted requests with just a single
round-trip (ie. a client can shut down, wake up with a different network
address, and still the first UDP package it sends to the server can be relied
and acted upon immediately). In this mode, there is no need for the device to
have a reliable source of entropy.

In practice, this means that OSCORE keys need to reside in writable
directories, are occasionally written to (the mechanisms of Appendix B.1 ensure
that writes are rare: they happen at startup, shutdown, and only occasionally
at runtime).

.. warning::

  This also means that stored OSCORE contexts must never be copied, only moved
  (or have the original deleted right after a copy).

  Where copies are unavoidable (eg. as part of a system backup), they must not
  be used unless it can be proven that the original was not written to at all
  after the backup was taken.

  When that can not be proven, the context must be deemed lost and
  reestablished by different means.

OSCORE credentials
------------------

As an experimental format, OSCORE uses JSON based credentials files that
describes OSCORE or (D)TLS credentials.

For client, they indicate which URIs should be accessed using which OSCORE
context. For servers, they indicate the available OSCORE contexts clients could
use, and provide labels for them.

The keys and IDs themselves are stored in a directory referenced by the
credentials file; this allows the state writes to be performed independently.

.. _RFC8613: https://tools.ietf.org/html/rfc8613
.. _EDHOC: https://tools.ietf.org/html/draft-selander-lake-edhoc-01
.. _ACE-OSCORE: https://tools.ietf.org/html/draft-ietf-ace-oscore-profile-11
.. _B.2: https://tools.ietf.org/html/rfc8613#appendix-B.2

OSCORE example
--------------

This example sets up encrypted access to the file server demo from the generic
command line client.

.. note::

  Manual provisioning of OSCORE contexts is not expected to be a long-term
  solution, and meant primarily for initial experimentation.

  Do not expect the security contexts set up here to be usable indefinitely, as
  the credentials and security context format used by aiocoap is still in flux.
  Moreover, the expample will change over time to reflect the best use of
  OSCORE possible with the current implementation.

First, create a pair of security contexts:

``client1/for-fileserver/settings.json``::

  {
    "sender-id_hex": "01",
    "recipient-id_ascii": "file",
  
    "secret_ascii": "Correct Horse Battery Staple"
  }

``server/from-client1/settings.json``::

  {
    "recipient-id_hex": "01",
    "sender-id_ascii": "file",
  
    "secret_ascii": "Correct Horse Battery Staple"
  }

A single secret must only be used once -- please use something more unique than
the `standard passphrase`_.

With each of those goes a credentials map:

``client1.json``::

  {
    "coap://localhost/*": { "oscore": { "contextfile": "client1/for-fileserver/" } }
  }

``server.json``::

  {
    ":client1": { "oscore": { "contextfile": "server/from-client1/" } }
  }

Then, the server can be started::

  $ ./aiocoap-fileserver data-to-be-served/ --credentials server.json

And queried using the client::

  $ ./aiocoap-client coap://localhost/ --credentials client1.json
  <subdirectory/>; ct="40",
  <other-directory/>; ct="40",
  <README>

Note that just passing in those credentials does not on its own make the server
require encrypted communication, let alone require authorization. Requests
without credentials still work, and in this very example it'd need a network
sniffer (or increased verbosity) to even be sure *that* the request was protected.


Ways of implementing access controls, mandatory encryption and access control
are being explored - as are extensions that simplify the setup process.

.. _`standard passphrase`: https://xkcd.com/936/
