Installing aiocoap
==================

In most situations, it is recommended to install the latest released version of
aiocoap. If you do not use a distribution that has aiocoap packaged, or if you
use Python's virtual environments, this is done with

::

    $ pip3 install --upgrade "aiocoap[all]"

If ``pip3`` is not available on your platform, you can manually download and
unpack the latest ``.tar.gz`` file from the `Python package index`_ and run

::

    $ ./setup.py install


.. _installation-development:

Development version
-------------------

If you want to play with aiocoap's internals or consider contributing to the
project, the suggested way of operation is getting a Git checkout of the
project::

    $ git clone https://github.com/chrysn/aiocoap

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
.. _`choice of checkout directories`: https://pip.pypa.io/en/stable/reference/pip_install/#vcs-support

Slimmer installations
---------------------

As aiocoap does not strictly depend on many of the libraries that are installed
when following the above recommendations, a setup can be stripped down by
entering any combination of the below "extras" in the place of the ``all`` in
the above lines, or leaving out the ``[all]`` expression for a minimal
installation.

The extras currently supported are:

* ``linkheader``: Needed for generating and parsing files in RFC6690_ link
  format, eg. ``.well-known/core`` files. Running or interacting with a
  Resource Directory is impossible without this module, as are many other
  discovery steps that applications will want to do.

* ``oscore``: Required for the :mod:`aiocoap.transports.oscore` transport.

* ``tinydtls``: Required for using CoAP over DTLS.

* ``docs``: Installs tools needed to build the documentation (not part of
  ``all``).

Which libraries and versions are pulled in by this exactly is documented in the
``setup.py`` file.

.. _RFC6690: https://tools.ietf.org/html/rfc6690
