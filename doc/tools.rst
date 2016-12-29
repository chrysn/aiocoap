CoAP tools
==========

As opposed to the :doc:`examples`, programs listed here are not tuned to show
the use of aiocoap, but are tools for everyday work with CoAP implemented in
aiocoap. Still, they can serve as examples of how to deal with user-provided
addresses (as opposed to the fixed addresses in the examples), or of
integration in a bigger project in general.

.. toctree::
   aiocoap-client: A CoAP client that supports observations and proxying <module/aiocoap.cli.client>
   aiocoap-proxy: A command-line configurable forward and reverse proxy <module/aiocoap.cli.proxy>
   aiocoap-rd: A standalone resource directory server <module/aiocoap.cli.rd>

Those utilities are installed by `setup.py` at the usual executable locations;
during development or when working from a git checkout of the project, wrapper
scripts are available in the root directory. In some instances, it might be
practical to access their functionality from within Python; see the
:mod:`aiocoap.cli` module documentation for details.

All tools provide details on their invocation and arguments when called with
the ``--help`` option.

contrib
-------

Tools in the ``contrib/`` folder are somewhere inbetween :doc:`examples` and
the tools above; the rough idea is that they should be generally useful but not
necessarily production tools, and simple enough to be useful as an inspiration
for writing other tools; none of this is set in stone, though, so that area can
serve as a noncommittal playground.

There is currently onely one tool in there:

* ``aiocoap-fileserver``: Serves the current directory's contents as CoAP
  resources, implementing directory listing and observation. No write support
  yet.
