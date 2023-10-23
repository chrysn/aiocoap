pyodide and Jupyter
===================

aiocoap can be run in a Python interpreter that is running in the browser
called pyodide_.
See :doc:`the its section in the installation instructions <guidedtour>`
for how to install in this environment.

The recommended way to use pyodide is through a `Jupyter notebook`_.
In a new "Notebook" of type "Python (Pyodide)",
first perform the installation steps,
and then use aiocoap like in the rest of the :doc:`guidedtour`.

Beware that when running in a web browser,
no general purpose UDP or TCP connectins can be created.
The only transport that is available is the client role of :mod:`CoAP over WebSockets <aiocoap.transports.ws>`;
any attempt to send requests to ``coap://``, ``coaps+tcp://`` or similar will fail
with "RuntimeError: No request interface could route message" (or a NotImplementedError).
Also, browsers are picky about when they allow unencrypted HTTP connections,
so the unsecure ``coap+ws://`` may be unavailable as well, leaving only ``coaps+ws://``.
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

The ``./contrib`` directory of the aiocoap source code
contains some example IPython notebooks that can be run right away.

   .. _pyodide: https://pyodide.org/
.. _`Jupyter notebook`: https://jupyter.org/try-jupyter
