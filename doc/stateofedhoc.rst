.. meta::
  :copyright: SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
  :copyright: SPDX-License-Identifier: MIT

EDHOC in aiocoap
================

Introducing EDHOC
-----------------

EDHOC (RFC9528_) is a key establishment protocol that shares many desirable
properties of :doc:`OSCORE <stateofoscore>`: It can use any CoAP transport (as
well as HTTP), and can traverse and benefit from proxies without granting them
access to the communication.

.. _RFC9528: https://tools.ietf.org/html/rfc9528

Using EDHOC in aiocoap
----------------------

EDHOC credentials can be stored in the same JSON/CBOR/EDN based credentials
files used with OSCORE and (D)TLS.

For a client, a single entry describes both the client-side and the server-side
credentials, as well as the URI(s) for which to use them. For a server, the
presented credential for any requested origin (URI excluding the path, as that
is the information available during EDHOC) is stored in one record, and one
record per client lists and labels the known peers.

EDHOC example
-------------

This example sets up encrypted access to the file server demo from the generic
command line client.

On the server side, generate a key for the server:

.. code-block:: shell-session

    $ aiocoap-keygen generate fileserver.cosekey --kid 0a
    {14: {8: {1: {1: 2, 2: h'0a', -1: 1, -2: ..., -3: ...}}}}

.. note:: Setting a key ID is required to later send the credential by key ID,
   which enables sending the own credential "by key ID" (which is more compact).

The output of this is a public key, which goes into the credential file you create next as ``fileserver.cred.diag``::

    {
      "coap://[::1]/*": {                   # replace with own pubic address
        "edhoc-oscore": {                   # or leave for local testing
          "suite": 2,
          "method": 3,
          "own_cred_style": "by-key-id",
          "own_cred": ...,                  # replace dots with the {14:...}
                                            # from before
          "private_key_file": "fileserver.cosekey",
        }
      },
    }

Now over to the client:

.. code-block:: shell-session

    $ aiocoap-keygen generate client.cosekey --kid 01
    {14: {8: {1: {1: 2, 2: h'01', -1: 1, -2: ..., -3: ...}}}}

Likewise, create a credential file we call ``client.cred.diag``::

    {
      "coap://[::1]/*": {
        "edhoc-oscore": {
          "suite": 2,
          "method": 3,
          "own_cred_style": "by-key-id",
          "own_cred": ...,                  # replace dots with the {14:...}
                                            # from before
          "private_key_file": "client.cosekey",
          "peer_cred": ...,                 # replace with {...} from server
        }
      },
    }

Finally, we have to extend the server's ``fileserver.cred.diag`` to accept this client --
we extend the last two lines to::

      },
      ":ourclient": { "edhoc-oscore": {
          "suite": 2,
          "method": 3,
          "peer_cred": ...,         # replace dots with own_cred from client
      }}
    }

Finally we can start the fileserver:

.. code-block:: shell-session

    $ ./aiocoap-fileserver --credentials fileserver.cred.diag

… and exchange data with EDHOC and OSCORE initiated by the client:

.. code-block:: shell-session

    $ aiocoap-client "coap://[::1]/" --credentials client.cred.diag
    … application/link-format content was re-formatted
    </.git/>; ct=40,
    </aiocoap/>; ct=40,
    [...]

.. warning:: This is a rudimentary setup that is just enough to show how things work.
   This does not yet perform any authorization control:
   the file server will still let any unauthenticated client
   perform the same operations as the newly authenticated client.

.. note:: As EDHOC support is extended, the steps described here should be
   vastly simplified:

   * The credentials file format needs an overhaul: entering peers should
     become as easy as creating entries in an ``.ssh/authorized_keys`` file.

   * Generating local identities should be more streamlined, with less
     copy-pasting involved.

   * unilateral authentication is supported by setting the peer's credentials
     to `{"unauthenticated": true}` -- but that needs some more explaining as
     to the security consequences.
