CoAP tools
==========

As opposed to the :doc:`examples`, programs listed here are not tuned to show
the use of aiocoap, but are tools for everyday work with CoAP implemented in
aiocoap. Still, they can serve as examples of how to deal with user-provided
addresses (as opposed to the fixed addresses in the examples), or of
integration in a bigger project in general.

.. toctree::
   :maxdepth: 1

   aiocoap-client: A CoAP client that supports observations and proxying <module/aiocoap.cli.client>
   aiocoap-proxy: A command-line configurable forward and reverse proxy <module/aiocoap.cli.proxy>
   aiocoap-rd: A standalone resource directory server <module/aiocoap.cli.rd>
   aiocoap-fileserver: A simple read-only file server with directory listings <module/aiocoap.cli.fileserver>

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

These tools are currently present:

* ``aiocoap-widgets``: Graphical software implementations of example CoAP
  devices as servers (eg. light bulb, switch). They should become an example of
  how CoRE interfaces and dynlinks can be used to discover and connect servers,
  and additionally serve as a playground for a more suitable Resource
  implementation.

  The GUI is implemented in Gtk3 using the gbulb_ asyncio loop.

* ``aiocoap-kivy-widget``: A similar (and smaller) widget implemented in Kivy_.

  As asyncio support is not merged in Kivy yet, be sure to build the library
  from `the asyncio pull request`_.

* ``oscore-plugtest``: Server and client for the interoperability tests
  conducted during the development of OSCORE.

  The programs in there are also used as part of the test suite.

* ``rd-relay``: An experiment of how much a host must implement if it is to be
  discovered during a Resource Directory discovery process, but does not serve
  as the full resource directory itself and redirects the client there.

.. _gbulb: https://github.com/nathan-hoad/gbulb
.. _Kivy: https://kivy.org/
.. _`the asyncio pull request`: https://github.com/kivy/kivy/pull/5241
