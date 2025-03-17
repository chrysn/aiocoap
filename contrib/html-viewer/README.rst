.. meta::
  :copyright: SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
  :copyright: SPDX-License-Identifier: MIT

====================
CoAP Resource Viewer
====================

This demo program provides a browser-like minimal viewer for CoAP resources.

To use it, place the files in this directory on a web server::

    $ python3 -m http.server

and go to <http://localhost:8080/##coaps+ws://demo.coap.amsuess.com/.well-known/core>
(which immediately accesses the indicated demo CoAP resource).

When started, the application loads up pyodide_ and styles from the web,
loads aiocoap from PyPI_ (i.e., it pulls in the released version rather than the local copy),
and then accesses CoAP resources through CoAP-over-WebSockets.

If a CoAP cross-proxy is configured in the application's settings,
CoAP resources on other transports can be reached as well.

A public instance of this is running at <https://coap.amsuess.com/view/>.

.. _pyodide: https://pyodide.org/en/stable/
.. _PyPi: https://pypi.org/
