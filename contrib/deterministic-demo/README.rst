Deterministic OSCORE demo
=========================

This shows the implementation of cachable-oscore_ that comes with aiocoap as an experimental extension.

.. _cachable-oscore: https://tools.ietf.org/html/draft-amsuess-core-cachable-oscore-01

Security error
--------------

(A warning would really be understating it)

This uses statically configured keys for both parties to be nice and slim as a demo.

As a consequence, as soon as the server is started a second time, it will produce responses with the same partial IVs,
resulting in nonce reuse and thus probably the loss of all security properties.

(It doesn't have any to start with because the private keys are hard-coded in the files...)

Usage
-----

* Monitor traffic on your loopback interface
* Run the server
* Run the client
* Observe how two identical (except for transport details like token and message ID) requests are sent,
  and how different responses are created, signed (that's why they are large), returned and accepted by the client.
