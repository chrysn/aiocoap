CoAP tools
==========

As opposed to the :doc:`examples`, programs listed here are not tuned to show
the use of aiocoap, but are tools for everyday work with CoAP implemented in
aiocoap. Still, they can serve as examples of how to deal with user-provided
addresses (as opposed to the fixed addresses in the examples), or of
integration in a bigger project in general.

* ``aiocoap-client``: A CoAP client that supports observations and proxying.
* ``aiocoap-proxy``: A command-line configurable forward and reverse proxy.

Those utilities are installed by `setup.py` at the usual executable locations;
during development or when working from a git checkout of the project, wrapper
scripts are available in the root directory. In some instances, it might be
practical to access their functionality from within Python; see the
:mod:`aiocoap.cli` module documentation for details.
