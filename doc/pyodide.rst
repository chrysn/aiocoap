.. meta::
  :copyright: SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
  :copyright: SPDX-License-Identifier: MIT

pyodide and Jupyter
===================

aiocoap can be run in a Python interpreter that is running in the browser
called pyodide_.

The recommended way to explore pyodide is through a `Jupyter notebook`_.
In a new "Notebook" of type "Python (Pyodide)",
first perform the installation steps,
and then use aiocoap like in the rest of the :doc:`guidedtour`.
Some ready-to-play examples at the end of the page can be run directly from the documentation.

See :ref:`the pyodide section in the installation instructions <installation-pyodide>`
for how to install in those environments.

Beware that when running in a web browser,
no general purpose UDP or TCP connections can be created.
The only transport that is available is the client role of :mod:`CoAP over WebSockets <aiocoap.transports.ws>`;
any attempt to send requests to ``coap://``, ``coaps+tcp://`` or similar will fail
with "RuntimeError: No request interface could route message" (or a NotImplementedError).
Also, browsers are picky about when they allow unencrypted HTTP connections,
so the unsecured ``coap+ws://`` may be unavailable as well, leaving only ``coaps+ws://``.
When going through the guided tour,
it is suggested to just use ``coaps+ws://demo.coap.amsuess.com/`` as a server,
as that is available without further setup.

Jupyter has the nice feature of allowing custom HTML to be shown in lieu of plain text \_\_repr\_\_esentations.
For some types, this is implemented;
for example, a message will show an HTML expandable view with options and payload,
where options and other constants have tooltips indicating their numeric values.
These features should be available not only when using pyodide,
but also when using aiocoap in a server side Python session in Jupyter,
in which case any networking limitations of the hosting virtual machine may apply.

.. _contrib-pyodide:

The ``./contrib`` directory of the aiocoap source code
contains some example IPython notebooks that can be run right away.
They already come with pre-populated output,
but can be stepped through block by block by repeatedly pressing Shift-Return.

* ``aiocoap-proxy.ipynb``:
  A minimal client program that accesses a public service through a public proxy.

  .. jupyterlite:: ../contrib/aiocoap-proxy.ipynb
     :new_tab: True
     :new_tab_button_text: Open in new tab

* ``aiocoap-server.ipynb``:
  A server program that bidirectionally exposes a browser interactive slider as a CoAP resource,
  and registers the server at a public Resource Directory
  (as a program running inside a browser is otherwise not easy to reach from outside).

  .. jupyterlite:: ../contrib/aiocoap-server.ipynb
     :new_tab: True
     :new_tab_button_text: Open in new tab

* ``edhoc-demo-server.ipynb``:
  A client program that interacts with a public EDHOC protected CoAP server.

  .. jupyterlite:: ../contrib/edhoc-demo-server.ipynb
     :new_tab: True
     :new_tab_button_text: Open in new tab

.. _pyodide: https://pyodide.org/
.. _`Jupyter notebook`: https://jupyterlite-pyodide-kernel.readthedocs.io/en/latest/_static/lab/
