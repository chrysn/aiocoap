Frequently Answered Questions
=============================

(Not *actually* asked frequently -- actually, this is a bunch of notes that users of the library should probably see at some point,
while it is not clear where to better put them).

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
