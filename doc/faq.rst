Frequently Answered Questions
=============================

(Not *actually* asked frequently -- actually, this is a bunch of notes that users of the library should probably see at some point,
while it is not clear where to better put them).

* **Which platforms are supported?**

  aiocoap requires Python 3.7
  (or PyPy 3.7),
  and should run on all operating systems supported by Python.

  Development and automated tests run on Linux, and this is where all listed features are supported.

  aiocoap generally runs on FreeBSD, Windows and macOS as well.
  Tests on FreeBSD are conducted manually;
  for Windows and macOS it's all largely relying on user feedback
  tracked in the `bug tracker for portability issues <https://github.com/chrysn/aiocoap/labels/platform%20support>`_.

  Note that the main CoAP-over-UDP transport :mod:`udp6<aiocoap.transports.udp6>` is only on-by-default on Linux
  because other platforms have no way of receiving network errors from an unconnected socket.
  The simpler UDP transports used on the other platforms do not support all features,
  and in particular lack multicast support.

  aiocoap is agnostic of the backing asyncio implementation
  as long as it implements the functionality required by the transport
  (``add_reader`` for udp6, ``sockname`` extra for role reversal on simple6).
  It is known to work with uvloop_ and gbulb_.

.. _uvloop: https://uvloop.readthedocs.io/
.. _gbulb: https://github.com/nathan-hoad/gbulb

* **How can a server be scaled up to use multiple cores?**

  Python is often considered weak around threading.
  While setups with multiple asyncio worker should conceptually work,
  the easiest way to parallelize is just to have multiple instances of your server running at the same time.
  This works when transports and platform support the SO_REUSEPORT option
  (this is the case on Linux with the default transports, but never on Windows),
  with which incoming requests are dispatched to any of the processes serving the port by the operating system.

  This requires an application design that has all its persistence managed outside the server process;
  that is typically the case with file system or database backed servers.

  (aiocoap internally does hold some state, but that is always per client,
  and the load balancing typically ensures that requests from the same client wind up in the same process.)


* **Why do I get a "The transport can not be bound to any-address." error message?**

  For your platform, the ``simplesocketserver`` module was selected.
  See :mod:`the simplesocketserver documentation<aiocoap.transports.simplesocketserver>` for why it can not bind to that address.

* **How is multicast supported?**

  Support for multicast is currently limited.

  On the server side, things are mostly ready.
  Groups are joined :meth:`at server creation<aiocoap.protocol.Context.create_server_context>`.

  On the client side, requests to multicast addresses can be sent,
  and while they are treated adaequately on the protocol level (eg. will not send CON requests),
  the :meth:`request interface<aiocoap.protocol.Context.request>` only exposes the first response.
  Thus, it can be used in discovery situations as long as only one response is processed,
  but not yet to its full power of obtaining data from multiple devices.

  Note that multicast requests often require specification of an interface,
  as otherwise the request is underspecified.
  Thus, a typical command line request might look like this::

     ./aiocoap-client coap://'[ff02::fd%eth0]'/.well-known/core --non

* **aiocoap fails to start if IPv6 is disabled system-wide.**

  Yes. `Don't do that`__
  It is not a supported mode of operation with the default implementation.

  .. __: https://howtodisableipv6.com/

  Background details:

  The default transport of aiocoap uses APIs that are well specified for IPv6 and work there for both IPv4 and IPv6 packets.
  Explicitly re-implementing everything on v4 would not only be needless extra work,
  it would also be a portability problem as unlike for IPv6, the interfaces are not specified platform independenlty for IPv4.
  Moreover, that mode would be error prone because it wouldn't receive regular testing.
