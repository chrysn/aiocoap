CoAP API design notes
=====================

This documentation chapter is not a full-fledged guide yet;
rather, it highlights some points of how CoAP is expressed in aiocoap.

* Library as a proxy:

  A CoAP library and API can, to some extent, be viewed
  as a CoAP proxy and a CoAP transport protocol, respectively.

  This shapes what the library can do, and makes guidance on how to do it accessible --
  for CoAP specification describe what proxies may do but say nothing on APIs.

  For example, splitting up large messages into block-wise chunks is something aiocoap does unless asked specificially not to;
  in its operation, it follows the guidance set out for proxies in RFC7959.
  Likewise, this is what justifies that aiocoap intermittently drops observe notifications.
  (Future releases might even take on intermediate proxies due to discovered alternative protocols).

  On the flip side, going all the way with this would mean that
  the application gets no choice in properties lost across proxies:
  The application could not decide whether reliable transport should be used.
  Furthermore, applied in full, the application could not use any proxy-unsafe options not suported by the library.

  In aiocoap, a balance is attempted.
  It behaves like a proxy for some convenience operations,
  which can be disabled as needed.
  It still allows the application author to set message properties for the first hop,
  and does not reject messages with proxy-unsafe options
  (trusting that no new proxy unsafe options are unsafe for the limited thing the library does).

* Messages as exchange objects:

  In aiocoap, requests and responses on the server and client side
  are handed to the application as CoAP messages.

  This gives the application a lot of flexibility in terms of setting and reacting to options;
  it allows application authors to explore extensions to CoAP.
  It is also the style of API used by libcoap and gcoap / nanocoap.
  On the other hand, it makes it relatively verbose to write applications
  that exclusively operate on predefined patterns
  (like objects that can be rendered into a representation depending on content format negotiation,
  or getter-setter patterns using GET and PUT).
  Simplified handlers for such cases can be built on aiocoap;
  the ``contrib`` directory contains some exploratory examples.

  In combination with the abovementioned proxy paradigm,
  this can lead to some weirdness when messages are represented differently on different transports.
  The general approach currenlty taken is to build the application level messages
  like a CoAP-over-UDP message was treated if UDP messages could be arbitrarily long
  (or possibly, with future changes to the internal block-wise mechanisms, using BERT).
  Notably, this means that applications that set Observe numbers manually should pack them into a 4-byte integer
  (which the TCP transport would then elide);
  transports may, however, do any deduplication and then just forward to the application
  that there *is* still an Observe number set.
  This is all not set in stone, though, and open for further development.

  Handling of properties outside of code, options and payload
  is currently still a bit mixed:
  Most resides in custom attributes of the message
  (like :attr:`aiocoap.Message.remote` or :attr:`aiocoap.Message.mtype`);
  thes are generally treated as hints and not always fully applicable.
  Some properties are also transported in options even though they are not exactly fitting here;
  for example, the No-Response option is used in responses to indicate to the stack that no response should be set.
  The latter should be cleaned up.
