.. meta::
  :copyright: SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
  :copyright: SPDX-License-Identifier: MIT

Installing aiocoap
==================

.. note::

  The commands here will install aiocoap in your current environment.
  By default, that is your platform's user install directory.

  To keep that clean, or to use different sets or versions of libraries for different purposes,
  you may want to look into the `venv documentation`_,
  which explains both the concept of virtual environments
  and how they are used on different platforms.

  .. _`venv documentation`:  https://docs.python.org/3/library/venv

In most situations, it is recommended to install the latest released version of
aiocoap. This is done using a simple::

    $ pip3 install --upgrade "aiocoap[all]"

(In some cases, the program is called ``pip`` only).


.. _installation-development:

Development version
-------------------

If you want to play with aiocoap's internals or consider contributing to the
project, the suggested way of operation is getting a Git checkout of the
project::

    $ git clone https://github.com/chrysn/aiocoap
    $ cd aiocoap

You can then use the project from that location, or install it with

::

    $ pip3 install --upgrade ".[all,docs]"

If you need to install the latest development version of aiocoap but do not
plan on editing (eg. because you were asked in the course of a bug report to
test something against the latest aiocoap version), you can install it directly
from the web::

    $ pip3 install --upgrade "git+https://github.com/chrysn/aiocoap#egg=aiocoap[all]"

With the ``-e`` option, that is also a viable option if you want to modify
aiocoap and pip's `choice of checkout directories`_ is suitable for you.

.. _`Python package index`: https://pypi.python.org/pypi/aiocoap/
.. _`choice of checkout directories`: https://pip.pypa.io/en/stable/topics/vcs-support/#editable-vcs-installs

Common errors
-------------

When upstream libraries change, or when dependencies of used libraries are not
there (eg. no C compiler, C libraries missing), the installation process can fail.

On Debian based systems, it helps to install the packages ``python3-dev``,
``build-essential``, ``autoconf`` and ``automake``; generally, the error output will
contain some hints as to what is missing.

As a workaround, it can be helpful to not install with all extras, but replace the
``all`` with the extras you actually want from the list below. For example, if
you see errors from DTLSSocket, rather than installing with ``[all,docs]``, you
can leave out the ``tinydtls`` extra and install with
``[oscore,prettyprint,docs]``.

Slimmer installations
---------------------

As aiocoap does not strictly depend on many of the libraries that are installed
when following the above recommendations, a setup can be stripped down by
entering any combination of the below "extras" in the place of the ``all`` in
the above lines, or leaving out the ``[all]`` expression for a minimal
installation.

The extras currently supported are:

* ``oscore``: Required for the :mod:`aiocoap.transports.oscore` transport,
  as well as for using EDHOC.

* ``tinydtls``: Required for using CoAP over DTLS.

* ``ws``: Required for using CoAP over WebSockets.

* ``prettyprint``: Allows using the ``--color`` and ``--pretty-print`` options
  of :doc:`module/aiocoap.cli.client` or fancy HTML output.

* ``docs``: Installs tools needed to build the documentation (not part of
  ``all``).

* ``linkheader``: Originally needed for generating and parsing files in
  RFC6690_ link format, eg. ``.well-known/core`` files. This extra does not
  contain any external dependencies, but was left in place for compatibility.

Which libraries and versions are pulled in by this exactly is documented in the
``pyproject.toml`` file.

.. _RFC6690: https://tools.ietf.org/html/rfc6690

.. _installation-pyodide:

On pyodide
----------

aiocoap can be run in a Python interpreter that is running in the browser
called pyodide_.

When using pyodide (either directly or through a `Jupyter notebook`_),
``pip`` is unavailable, but there is ``micropip`` to replace it.
Installation is then done directly in the Python environment using::

    >>> import micropip
    >>> await micropip.install("aiocoap[all]")

See the :doc:`pyodide` section of the documentation on how aiocoap can be used there.

.. _pyodide: https://pyodide.org/
.. _`Jupyter notebook`: https://jupyterlite-pyodide-kernel.readthedocs.io/en/latest/_static/lab/
..
   not using the more prominent
   .. _`Jupyter notebook`: https://jupyter.org/try-jupyter/
   (here and in other places around the docs)
   because that's still on pyodide 0.27 with ABI 2024

Using unreleased versions on pyodide
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The latest main version is made available through aiocoap's CI runs,
and can be used like this::

    >>> import micropip
    >>> await micropip.install(
    ...     "aiocoap[all]",
    ...     index_urls=["https://coap.amsuess.com", "PYPI"]
    ... )

That index not only contains the latest aiocoap versions,
but also a suitable version of the lakers-python dependency.
(Generally, that is package is regularly updated in pyodide,
but the notebook may not be using the latest pyodide yet).

..
    It's not going through Codeberg pages because that can do correct
    Content-Format (on regular pages) or CORS (on raw.codeberg.page), but
    micropip needs both at the same time.

To test a local build with pyodide,
get a Git checkout as described for development above, and run::

    python3 -m build

Then, copy the newly created file ``dist/aiocoap-${VERSION}-py3-none-any.whl``
to a file server on the public web.
Do not rename the file, as it is parsed by micropip.
Note that the server may need some CORS_ setup to allow loading of the file from foreign web sites.
For that reason, running the ``http.server`` module as a web server on localhost creates an insufficient server
(unless pyodide is also served from the same host).

.. _CORS: https://en.wikipedia.org/wiki/Cross-origin_resource_sharing
