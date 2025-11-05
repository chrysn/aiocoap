.. meta::
  :copyright: SPDX-FileCopyrightText: Christian Amsüss
  :copyright: SPDX-License-Identifier: MIT

Version 0.4.17
--------------

Enhancements
~~~~~~~~~~~~

* EDHOC requests now send the CRED_BY_VALUE EAD item.

  This allows use of unauthenticated servers
  (eg. in opportunistic encryption, or when only the client needs to be authenticated)
  when the server would only send a credential key ID by default.

Compatibility
~~~~~~~~~~~~~

* aiocoap-client now accepts the ``--no-sec`` option.

  This is currently a no-op, but as the defaults might change,
  this allows future scripts to use the option also with aiocoap versions starting from now.

* Tests were updated to run on released Python 3.14 images.

Errors and documentation
~~~~~~~~~~~~~~~~~~~~~~~~

* Errors report unreachable IP versions more precisely.
* Errors from the simple6 transport now raise ``NetworkError`` like the other transports
  (following general documentation).
* The ``ValueError`` from attempting to send CON messages to multicast through the udp6 trnasport
  is now subclassed to ``ConToMulticast``,
  and produces more useful error messages.
* Many spelling fixes.

Packaging
~~~~~~~~~

* Citation data is now provided in [citation file format](https://citation-file-format.github.io/).

* ``setup.py`` was removed; this was not used any more in any workflow but providing citation data.

Version 0.4.16
--------------

Enhancements
~~~~~~~~~~~~

* Messages have a ``.direction`` (incoming or outgoing); this is managed by the library.

  This simplifies calls such as ``.get_request_uri()``, which works without an extra ``local_is_server=`` parameter now.

* Message representation is enhanced based on direction.

* The draft option Uri-Path-Abbrev is now processed by server sites.

Bugfixes
~~~~~~~~

* The aiocoap-client invocation has been fixed for pip installed packages.
* Transport tuning is now applied to the transport also for OSCORE requests.

Deprecations
~~~~~~~~~~~~

* Setting the token, MID or message type (mtype, like CON or NON) in a message is deprecated.
  The message type can now be set using transport_tuning=Reliable/Unreliable instead.

  This serves to decouple CoAP's sub-layers, and prepares the addition of other transports with optional reliability.

Version 0.4.15
--------------

Documentation and examples
~~~~~~~~~~~~~~~~~~~~~~~~~~

* Jupyter examples were simplified.
* Documentation now includes live Jupyter notebooks to facilitate live usage.
* Fixes to the guided tour, EDHOC and OSCORE recommendations.
* Removed obsolete information.

Libraries and compatibility
~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Python 3.14 is now supported.
* Support for gbulb was removed.
* Tests were migrated from bespoke wrapper to using unittest's async mechanisms.
* Use of the Lakers library was updated to 0.6.0, supporting a wider range of correct EDHOC interactions.

Building and metadata
~~~~~~~~~~~~~~~~~~~~~

* Code was moved back from src/aiocoap/ to aiocoap/.
* Examples for Android were updated and support Rust dependencies.
* License information now correctly captures vendored BSD-3-Clause libraries.
* Building now requires setuptools 77 or later.
* Dependencies of extras were updated to no longer introduce unneeded or useless dependencies.

Bugfixes
~~~~~~~~

* aiocoap-client now properly reports file access errors.
* A reference cycle in WebSockets transports was resolved.
* Various tests were fixed or added (including coverage of aiocoap-client --interactive).
* Missing dependencies (EDHOC requires cbor-diag for loading credentials) were declared.

Other
~~~~~

* Cacheable OSCORE aligned with initial working group draft.
* Workarounds for unsupported Python versions were dropped.

Version 0.4.14
--------------

This is mainly a CLI and integration update.

Enhancements in aiocoap-client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* --interactive mode now takes some arguments (eg. --proxy and --credentials) both globally and per request.
  Options like --version were removed from inside interactive mode.
* -v/--verbose now prints sent and received messages; add more -v to increase the log levels.
* Sufficiently many -v now produce log messages beyond DEBUG.

Dependencies
~~~~~~~~~~~~

* The websockets module is now also supported in its versions 14 and 15.
* colorlog was added as an optional dependency in the ``[prettyprint]`` feature.

Minor enhancements and fixes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Explicit string representation of CoAP option numbers was added.
* The repr of ContentFormat elide the encoding in the trivial case.
* Workarounds were dropped in the contrib/html-viewer and for websockets.
* The server example is now more explicit in its content formats.
* Testing of doctests was restored.

Version 0.4.13
--------------

Enhancements
~~~~~~~~~~~~

* Lakers was updated to 0.5, enabling
  - a larger set of CCS credentials, and
  - using EDHOC message 3 without the EDHOC option optimization.
* OSCORE server contexts can now be registered at a Resource Directory, showing all resources.
* Fileserver only sends Block2 and ETag on demand; ETag length can be configured.

Breaking changes
~~~~~~~~~~~~~~~~

* Group OSCORE was updated to reflect the latest draft version -23, and thus incompatible with groups on older versions.

Minor enhancements
~~~~~~~~~~~~~~~~~~

* Logging of OSCORE contexts was enhanced; a tightly checked ``AIOCOAP_REVEAL_KEYS`` variable was introduced to avoid logging secrets in regular operation.
* CLI tools now consistently support --version.
* The DTLS test can be run as a server (like other tests).
* Various error handling fixes, especially on the shutdown path.
* Various documentation updates, addressing OpenSSF best practice concerns.
* Failed CoAP transport selection now raises a ``NoRequestInterface`` error.
* On pyodide, socket based transports are not initialized.
  (They would have failed at runtime inside the standard library).
* The ``ProxyForarder`` (client side proxying) is fixed to correctly send requests cross-transport.
* The RD registrant can now use its ``link_source`` argument.

Contrib
~~~~~~~

* An HTML/WASM based CoAP viewer example was added.

Version 0.4.12
--------------

Enhancements
~~~~~~~~~~~~

* Better errors are shown when using malformed (esp. incomplete) URIs, eg. on ``aiocoap-client hostname:port``.
* Support for ephemeral identities (``{"unauthenticated: true}``) is extended to the local side.
* OSCORE groupcomm is updated to the latest draft version.

Breaking changes
~~~~~~~~~~~~~~~~

* By updating to lakers 0.4.1, the EDHOC implementation now complies with the specification regarding credentials-by-value;
  due to bugs in prior versions, this breaks EDHOC establishment with credentials-by-value with later versions.
  The common case of credentials by KID is unaffected.

Bug fixes
~~~~~~~~~

* Cases of invalid URIs are reported more reliably, rather than producing incorrect requests.

Internal refactoring
~~~~~~~~~~~~~~~~~~~~

* CI and main source hosting now run on codeberg.
* Tests are made resilient to high system load.

Version 0.4.11
--------------

New features
~~~~~~~~~~~~

* Group OSCORE is updated to draft version -21.
* max_regular_block_size_exp can now be set on remotes by the client.
  This allows influencing both the Block1 and the Block2 size.
* EDHOC: Allow private keys to be generated in RAM, and specified directly in the credentials file.

Examples
~~~~~~~~

* Add EDHOC demo for Jupyter.

Minor fixes
~~~~~~~~~~~

* IP addresses are subjected to URI syntax normalization.
* Avoid mixups between TLS and non-TLS contexts.
* Send Uri-Host and Uri-Scheme in manually constructed EDHOC message.

Version 0.4.10
--------------

New features
~~~~~~~~~~~~

* Initial experimental support for EDHOC key establishment was added.
* CLI: New aiocoap-keygen command was added.
* Credentials can be processed as CBOR Diagnostic Notation (EDN).
* aiocoap.cli.defaults can be run as a module.

Deprecations
~~~~~~~~~~~~

* OSCORE: The context argument "contextfile" was renamed to "basedir".

Minor fixes
~~~~~~~~~~~

* Many indenting and quoting changes due to the switch to enforced ruff lints and formatting.
* Various broken, missing and duplicate references fixed in the documentation.
* Doctest failure in 0.4.9 _repr_html_ was fixed.

Version 0.4.9
-------------

This is a bugfix release to restore functionality when used through Jupyter and in Python's optimized mode.

Bug fixes
~~~~~~~~~

* enum: Fix visibility of _repr_html_ on Python versions < 3.13.
* numbers: Don't export _code, which is only present with __debug__.


Version 0.4.8
-------------

Compatibility
~~~~~~~~~~~~~

* Block-wise requests now send Size1

Error handling
~~~~~~~~~~~~~~

* Errors raised through the udp6 interface now report name and description in
  addition to their error number.
* Many errors now have an ``.extra_help()`` method, which is shown in
  aiocoap-client to guide the user's debugging.
* Some non-aiocoap errors being raised as a result of network errors were
  turned into error.NetworkError.
* All CoAP error response codes now have a corresponding
  ``ConstructionRenderableError`` and can thus be raised easily from handers.

Platform support
~~~~~~~~~~~~~~~~

* Support for Python versions below 3.10 was dropped.
* Inconsistent platform implementations of AI_V4MAPPED and AI_ADDRCONFIG are
  now worked around by custom implementations of the lookup process.
* Android is now supported.
* Python 3.13 is now supported.
* Kivy examples were updated to current mainline Kivy.
* gbulb support is being phased out in favor of pygobject's upcoming native async support.

Infrastructure
~~~~~~~~~~~~~~

* Build system was modernized and migrated to pyproject.toml.
  Tests are now run using tox or ``python3 -m unittest``
* Type annotations are now tested using mypy.
* The ``ExtensibleIntEnum`` type underlying ``ContentFormat`` and
  ``OptionNumber`` was altered to now use ``enum.IntEnum`` as its base.

Deprecations
~~~~~~~~~~~~

* The request.observation.register_callback / register_errback interface is
  deprecated in favor of the asynchronous iteration interface (aiter).
* Setting media type and encoding on a ContentFormat is deprecated, use
  ``.define(...)`` instead.
* ``OptionNumber.OBJECT_SECURITY`` is deprecated; it is an alias for ``.OSCORE``.
  (Same goes for the ``message.opt.object_security`` attribute).

Minor fixes
~~~~~~~~~~~

* aiocoap-client can now use the iPATCH method.
* aiocoap-client output colors were improved.
* cbor-diag is recognized as a prerequisite for pretty printing.
* Corner cases for SSL configuration for WebSockets were fixed.
* Documentation updates, including references to pyodide.
* Corner cases of implicit observation cancellation were fixed.
* Access to cryptography internals now uses the proper public interfaces.


Version 0.4.7
-------------

Compatibility
~~~~~~~~~~~~~

* Group OSCORE updated to -17.

  The setup of group contexts requires altered parameters, as the descriptions
  of these contexts changed in the underlying specification.

Minor fixes
~~~~~~~~~~~

* Several minor documentation fixes.


Version 0.4.6-alpha3
--------------------

Bug fixes
~~~~~~~~~

* Include vendored modules in sdist and wheels.


Version 0.4.6-alpha2
--------------------

Bug fixes
~~~~~~~~~

* ``request.get_request_uri()`` in a server handler now reports the URI with
  the correct path.
* Broken links fixed in documentation.

Meta
~~~~

* Updated copyright statements, now complying with reuse.software specs.
* LinkHeader dependency moved from unmaintained PyPI package into vendored copy
  to avoid trouble with missing .whl (wheel) files.


Version 0.4.6-alpha1
--------------------

CLI changes
~~~~~~~~~~~

* aiocoap-client now uses CBOR Diagnostic Notation both for pretty-printed
  output and when adjusting a ``--payload`` argument to a CBOR
  ``--content-format``. This should be a compatible change for users who
  previously used JSON for input, but needs adjustments for users who used
  Python literals.

* CBOR sequences are now recognized for pretty-printing, and accepted (wrapped
  in an array) for ``--payload`` format adjustment.

New features
~~~~~~~~~~~~

* Initial support for pyodide (eg. in Jupyter):

  * The websockets client transport is made available through the browser's
    APIs.
  * Messages and other elements are available for HTML pretty-printing.

* Messages now have a ``.transport_tuning`` property, which may be overwritten
  to influence transmission characteristics.

Bug fixes
~~~~~~~~~

* BERT blocks are now extracted correctly.
* oscore: Constant with typo renamed (``COSE_COUNTERSI(NG→GN)ATURE0``).

Deprecations
~~~~~~~~~~~~

* numbers.constants: Transport related parameters are deprecated, use
  ``.transport_tuning`` (see above).


Version 0.4.5
-------------

Behavioral changes
~~~~~~~~~~~~~~~~~~

* RSTs are not sent on unrecognized responses any more unless the received
  message was a CON; the previous behavior was violating the specification.

Deprecations
~~~~~~~~~~~~

* UNSUPPORTED_MEDIA_TYPE is now formally deprecated, use
  UNSUPPORTED_CONTENT_FORMAT instead.

Minor enhancements
~~~~~~~~~~~~~~~~~~

* Fix tests for Python 3.11.
* Lower log level of "but could not match it to a running exchange" from warning to info.
* Shorten the string representation of message types (to "CON", "ACK" etc.)

Version 0.4.4
-------------

New features
~~~~~~~~~~~~

* Content-Format / Accept option now use a dedicated ContentFormat type.

  Applications should be unaffected as the type is still derived from int.

* Non-traditional responses are now experimentally supported by implementing
  ``.render_to_pipe()`` on a resource.

Deprecations
~~~~~~~~~~~~

* Building custom resources by inheriting from ``interfaces.Resource`` /
  ``interfaces.ObservableResource`` and implementing ``.render()`` etc. is
  deprecated. Instead, inherit from ``resource.Resource`` (recommended), or
  implement ``.render_to_pipe()`` (eg. when implementing a proxy).

* numbers.media_type and media_type_rev: Use the ContentFormat type's
  constructor and accessors instead.

Tools
~~~~~

* aiocoap-fileserver now has optiojnal write support, and ETag and If-* option
  handling.

* aiocoap-client now assembles and displays the Location-* options of
  responses.

* aiocoap-rd now has dedicated logging independent of aiocoap's.

* Various small fixes to aiocoap-rd.

* Help and error texts were improved.

Minor enhancements
~~~~~~~~~~~~~~~~~~

* Documentation now uses ``await`` idiom, as it is available even inside the
  asyncio REPL.

* The default cut-off for block-wise fragmentation was increased from 1024 to
  1124 bytes. This allows OSCORE to use the full inner block-wise size without
  inadvertently causing outer fragmentation, while still fitting within the
  IPv6 minimum MTU.

* Connection shutdown for TCP and WebSockets has been implemented, they now
  send Release messages and wait for the peer to close the connection.

* Type annotations are now used more widely.

* Library shutdown works more cleanly by not relying on the presence of the
  async loop.

* OSCORE contexts now only access the disk when necessary.

* OSCORE now supports inner block-wise transfer and observations.

* WebSocket servers can now pick an ephemeral port (when binding to port 0).

* Tasks created by the library are now named for easier debugging.

* Bugs fixed around handling of IP literals in proxies.

Internal refactoring
~~~~~~~~~~~~~~~~~~~~

* Pipes (channels for asynchronously producing responses, previously called
  PlumbingResponse) are now used also for resource rendering. Block-wise and
  observation handling could thus be moved away from the core protocol and into
  the resource implementations.

* Exception chaining was started to be reworked into explicit re-raises.

Version 0.4.3
-------------

Compatibility
~~~~~~~~~~~~~

* Fix compatibility with websockets 10.1.

Minor enhancements
~~~~~~~~~~~~~~~~~~

* Failure path fixes.

Version 0.4.2
-------------

New features
~~~~~~~~~~~~

* Experimental support for DTLS server operation (PSK only).

Tools
~~~~~

* aiocoap-client reports responder address if different from requested.
* aiocoap-rd is aligned with draft version -27 (e.g. using .well-known/rd).
* aiocoap-proxy can be registered to an RD.

Compatibility
~~~~~~~~~~~~~

* Group OSCORE updated to -11.
* Fixes to support Python 3.10, including removal of some deprecated idioms and
  inconsistent loop handling.

Examples / contrib
~~~~~~~~~~~~~~~~~~

* Demo for Deterministic OSCORE added.

Deprecations
~~~~~~~~~~~~

* util.quote_nonascii
* error.{RequestTimedOut,WaitingForClientTimedOut}
* Direct use of AsyncCLIDaemon from asynchronous contexts (replacement not
  available yet).

Minor enhancements
~~~~~~~~~~~~~~~~~~

* Resources can hide themselves from the listing in /.well-known/core.
* RD's built-in proxy handles block-wise better.
* Added __repr__ to TokenManager and MessageManager.
* Pretty printer errs gracefully.
* Failure path fixes.
* Documentation updates.
* Removed distutils dependency.

Internal refactoring
~~~~~~~~~~~~~~~~~~~~

* CI testing now uses pytest.
* dispatch_error now passes on exceptions.
* DTLS client cleaned up.
* Build process now uses the build module.

Version 0.4.1
-------------

* Fix Python version reference to clearly indicate the 3.7 requirement
  everywhere.

  A Python requirement of ">= 3.6.9" was left over in the previous release's
  metadata from earlier intermediate steps that accommodated PyPy's pre-3.7
  version.

Version 0.4
-----------

Multicast improvements
~~~~~~~~~~~~~~~~~~~~~~

* Multicast groups are not joined by default any more. Instead, groups and
  interfaces on which to join need to be specified explicitly. The previous
  mechanism was unreliable, and only joined on one (more or less random)
  interface.

* Network interfaces can now be specified in remotes of larger than link-local
  scope.

* In udp6, network interface are selected via PKTINFO now. They used to be
  selected using the socket address tuple, but that was limited to link-local
  addresses, but PKTINFO worked just as well for link-local addresses.

* Remote addresses in udp6 now have a ``netif`` property.

New features
~~~~~~~~~~~~

* The simple6 transport can now indicate the local address when supported by
  the platoforrm. This makes it a viable candidate for LwM2M clients as they
  often operate using role reversal.

* Servers (including the shipped examples) can now offer OSCORE through the
  OSCORE sitewrapper.

  Access control is only rudimentary in that the authorization information is
  not available in a convenient form yet.

* CoAP over WebSockets is now supported (in client and server role, with and
  without TLS). Please note that the default port bound to is not the HTTP
  default port but 8683.

* OSCORE group communication is now minimally supported (based on draft version
  10). No automated ways of setting up a context are provided yet.

  This includes highly experimental support for deterministic requests.

* DTLS: Terminating connections are now handled correctly, and shut down when
  unused.

  The associated refactoring also reduces the resource usage of DTLS
  connections.

Tools updates
~~~~~~~~~~~~~

* aiocoap-client: New options to

  * set initial Block1 size (``--payload-initial-szx``), and to
  * elide the Uri-Host option from requests to named hosts.

* aiocoap-client: CBOR input now accepts Python literals or JSON automatically,
  and can thus produce numeric keys and byte strings.

* aiocoap-client: Preprocessed CBOR output now works for any CBOR-based content
  format.

* resource-directory: Updated to draft -25.

* resource-directory: Compatibility mode for LwM2M added.

* resource-directory: Proxying extension implemented. With this, and RD can be
  configured to allow access to endpoints behind a firewalls or NAT.

* Example server: Add /whoami resource.

Dependencies
~~~~~~~~~~~~

* The minimum required Python version is now 3.7.
* The cbor library dependency was replaced with the cbor2 library.
* The dependency on the hkdf library was removed.
* The ge25519 library dependency was added to perform key conversion steps necessary for Group OSCORE.

Portability
~~~~~~~~~~~

* Several small adjustments were made to accommodate execution on Windows.
* FreeBSD was added to the list of supported systems (without any need for changes).

Fixes possibly breaking applications
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Some cases of OSError were previously raised in responses. Those are now all
  expressed as an aiocoap.error.NetworkError, so that an application only need
  to catch aiocoap.error.Error for anything that's expected to go wrong.

  The original error cause is available in a chained exception.

* Responses are not deduplicated any more; as a result, less state is kept in
  the library.

  As a result, separate responses whose ACKs get lost produce an RST the second
  time the CON comes. This changes nothing about the client-side handling
  (which is complete either way with the first response), but may upset servers
  that do not anticipate this allowed behavior.

Minor fixes
~~~~~~~~~~~

* The repr of udp6 addresses now shows all address components.
* Debug information output was increased in several spots.
* The ``loop=`` parameter was removed where it is deprecated by Python 3.8.
* asyncio Futures are created using create_future in some places.
* Binding to port 0 works again.
* The file server's registration at an RD was fixed.
* File server directories can now use block-wise transfer.
* Server errors from rendering exceptions to messages are now caught.
* Notifications now respect the block size limit.
* Several improvements to the test infrastructure.
* Refactoring around request processing internals (PlumbingRequest) alleviated potential memory leaks.
* Update option numbers from draft-ietf-echo-request-tag-10.
* Various proxying fixes and enhancements.
* TLS: Use SNI (Python >= 3.8), set correct hostinfo based on it.
* Internally used NoResponse options on responses are not leaked any more.
* Timeouts from one remote are now correctly propagated to all pending requests.
* Various logging improvements and changes.
* udp6: Show warnings when operating system fails to deliver pktinfo (happens with very old Linux kernels).
* Reduce installation clobber by excluding tests.
* Enhanced error reporting for erroneous ``coap://2001:db8::1/`` style URIs
* Improve OSCORE's shutdown robustness.
* Sending to IPv4 literals now does not send the Uri-Host automatically any more.

Version 0.4b3
-------------

Behavioral changes
~~~~~~~~~~~~~~~~~~

* Responses to NON requests are now sent as NON.

Portability
~~~~~~~~~~~

* All uses of SO_REUSEPORT were changed to SO_REUSEADDR, as REUSEPORT is
  considered dangerous by some and removed from newer Python versions.

  On platforms without support for that option, it is not set. Automatic
  load-balancing by running parallel servers is not supported there.

* The udp6 module is now usable on platforms without MSG_ERRQUEUE (ie. anything
  but Linux). This comes with caveats, so it is still only enabled by default
  on Linux.

  The required constants are now shipped with aiocoap for macOS for the benefit
  of Python versions less than 3.9.

Minor fixes
~~~~~~~~~~~

* More effort is made to sync OSCORE persistence files to disk.
* Memory leakage fixes on server and client side.
* Option numbers for Echo and Request-Tag were updated according to the latest
  draft version.

Other
~~~~~

* FAQ section started in the documentation.
* With ``./setup.py test`` being phased out, tests are now run via tox.

Version 0.4b2
-------------

New features
~~~~~~~~~~~~

* OSCORE: Implement Appendix B.1 recovery. This allows the aiocoap program to
  run OSCORE without writing sequence numbers and replay windows to disk all
  the time. Instead, they write pessimistic values to disk that are rarely
  updated, write the last values on shutdown. In the event of an unclean
  shutdown, the sender sequence number is advanced by some, and the first
  request from a client is sent back for another roundtrip using the Echo
  option.

  An aiocoap client now also contains the code required to transparently
  resubmit requests if a server is in such a recovery situation.

* OSCORE: Security contexts are now protected against simultaneous use by
  multiple aiocoap processes. This incurs an additional dependency on the
  ``filelock`` package.

Breaking changes
~~~~~~~~~~~~~~~~

* OSCORE: The file format of security context descriptions is changed. Instead
  of the previous roles concept, they now carry explicit sender and recipient
  IDs, and consequently do not take a role parameter in the credentials file
  any more.

  The sequence number format has changed incompatibly.

  No automatic conversion is available. It is recommended to replace old
  security contexts with new keys.

Minor fixes
~~~~~~~~~~~

* b4540f9: Fix workaround for missing definitions, restoring Python 3.5 support
  on non-amd64 platforms.
* b4b886d: Fix regression in the display of zone identifiers in IPv6 addresses.
* 5055bd5: The server now does not send RSTs in response to multicasts any
  more.
* OSCORE: The replay window used is now the prescribed 32bit large DTLS-like
  window.

Version 0.4b1
-------------

Tools
~~~~~

* aiocoap-client can now re-format binary output (hex-dumping binary files,
  showing CBOR files in JSON-like notation) and apply syntax highlighting. By
  default, this is enabled if the output is a terminal. If output redirection
  is used, data is passed on as-is.

* aiocoap-fileserver is now provided as a standalone tool. It provides
  directory listings in link format, guesses the content format of provided
  files, and allows observation.

* aiocoap-rd is now provided as a standalone tool and offers a simple CoRE
  Resource Directory server.

Breaking changes
~~~~~~~~~~~~~~~~

* Client observations that have been requested by sending the Observe option
  must now be taken up by the client. The warning that was previously shown
  when an observation was shut down due to garbage collection can not be
  produced easily in this version, and will result in a useless persisting
  observation in the background. (See <https://github.com/chrysn/aiocoap/issues/104>)

* Server resources that expect the library to do handle blockwise by returning
  true to ``needs_blockwise_assembly`` do not allow random initial access any
  more; this this is especially problematic with clients that use a different
  source port for every package.

  The old behavior was prone to triggering an action twice on non-safe methods,
  and generating wrong results in block1+block2 scenarios when a later ``FETCH
  block2:2/x/x`` request would be treated as a new operation and return the
  result of an empty request body rather than being aligned with an earlier
  ``FETCH block1:x/x/x`` operation.

* fdc8b024: Support for Python 3.4 is dropped; minimum supported version is now
  3.5.2.

* 0124ad0e: The network dumping feature was removed, as it would have been
  overly onerous to support it with the new more flexible transports.

* 092cf49f, 89c2a2e0: The content type mapped to the content format 0 was
  changed from "text/plain" (which was incorrect as it was just the bare media
  type) to the actual content of the IANA registry,
  'text/plain;charset="utf8"'. For looking up the content format, text/plain is
  is still supported but deprecated.

* 17d1de5a: Handling of the various components of a remote was unified into the
  .remote property of messages. If you were previously setting unresolved
  addresses or even a tuple-based remote manually, please set them using the
  ``uri`` pseudo-option now.

* 47863a29: Re-raise transport specific errors as aiocoap errors as
  aiocoap.error.ResolutionError or NetworkError. This allows API users to catch
  them independently of the underlying transport.

* f9824eb2: Plain strings as paths in add_resource are rejected. Applications
  that did this are very unlikely to have produced the intended behavior, and
  if so can be easily fixed by passing in ``tuple(s)`` rather than ``s``.

New features
~~~~~~~~~~~~

* 88f44a5d: TCP and TLS support added; TLS is currently limited to PKI
  certificates. This includes support for preserving the URI scheme in
  exchanges (0b0214db).
* a50da1a8: The credentials module was added to dispatch DTLS and OSCORE credentials
* f302da07: On the client side, OSCORE can now be used as a transport without
  any manual protection steps. It is automatically used for URIs for which a
  security context has been registered with the context's client credentials.
* 5e5388ae: Support for PyPy
* 0d09b2eb: NoResponse is now handled automatically. Handlers can override the
  default handling by setting a No-Response option on their response
  messages, whose value will them be examined by the library to decide whether
  the message is actually sent; the No-Response option is stripped from the
  outgoing message in the course of that (as it's actually not a response
  option).
* b048a50a: Some improvements on multicast handling. There is still no good
  support for sending a request to multicast and receiving the individual
  responses, but requests to multicast addresses are now unconditionally
  handled under the rules of multicast CoAP, even if they're used over the
  regular request interface (ie. sending to multicast but processing only the
  first response).
* c7ca0286: The software version used to run the server (by default, aiocoap's
  version) is now shown in .well-known/core using the impl-info relation.

Deprecations
~~~~~~~~~~~~

* 0d09b2eb: Returning a NoResponse sentinel value is now deprecated.

Assorted changes
~~~~~~~~~~~~~~~~

* Additions to the contrib/ collection of aiocoap based tools:

  - widgets, kivy-widgets
  - rd-relay

* 95c681a5 and others: Internal interfaces were introduced for the various CoAP
  sublayers.  This should largely not affect operation (though it does change
  the choice of tokens or message IDs); where it does, it's noted above in the
  breaking changes. 
* 5e5388ae, 9e17180e, 60137bd8: Various fixes to the OSCORE implementation,
  which is not considered experimental any more.
* Various additions to the test suite
* 61843d41: Asynchronous ``recvmsg`` calling (as used by the udp6 backend) was
  reworked from monkey-patching into using asyncio's ``add_reader`` method, and
  should thus now be usable on all asyncio implementations, including uvloop
  and gbulb.
* 3ab14c49: .well-known/core filtering will now properly filter by content
  format (ct=) in the presence of multiple supported content types.
* 9bd612de: Fix encoding of block size 16.
* 029a8f0e: Don't enforce V4MAPPED addresses in the simple6 backend. This makes
  the backend effectively a simple-any backend, as the address family can be
  picked arbitrarily by the operating system.
* 8e93eeb9: The simple6 backend now reuses the most recently used 64 sockets.
* cb8743b6: Resolve the name given as binding server name. This enables
  creating servers bound exclusively to a link-local address.
* d6aa5f8c: TinyDTLS now pulls in a more recent version of DTLSSocket that has
  its version negotiation fixed, and can thus interoperate with recent versions
  of libcoap and RIOT's the pending support for DTLS on Gcoap.
* 3d9613ab: Errors in URI encoding were fixed

Version 0.4a1
-------------

Security fixes
~~~~~~~~~~~~~~

* 18ddf8c: Proxy now only creates log files when explicitly requested
* Support for secured protocols added (see Experimental Features)

Experimental features
~~~~~~~~~~~~~~~~~~~~~

* Support for OSCORE (formerly OSCOAP) and CoAP over DTLS was included

  These features both lack proper key management so far, which will be
  available in a 0.4 release.

* Added implementations of Resource Directory (RD) server and endpoint

* Support for different transports was added. The transport backends to enable
  are chosen heuristically depending on operating system and installed modules.

  * Transports for platforms not supporting all POSIX operations to run CoAP
    correctly were added (simple6, simplesocketserver). This should allow
    running aiocoap on Windows, MacOS and using uvloop, but with some
    disadvantages (see the the respective transport documentations).

Breaking changes
~~~~~~~~~~~~~~~~


* 8641b5c: Blockwise handling is now available as stand-alone responder.
  Applications that previously created a Request object rather than using
  Protocol.request now need to create a BlockwiseRequest object.
* 8641b5c: The ``.observation`` property can now always be present in
  responses, and applications that previously checked for its presence should
  now check whether it is None.
* cdfeaeb: The multicast interface using queuewithend was replaced with
  asynchronous iterators
* d168f44: Handling of sub-sites changed, subsites' root resources now need to
  reside at path ``("",)``

Deprecations
~~~~~~~~~~~~

* e50e994: Rename UnsupportedMediaType to UnsupportedContentFormat
* 9add964 and others: The ``.remote`` message property is not necessarily a
  tuple any more, and has its own interface
* 25cbf54, c67c2c2: Drop support for Python versions < 3.4.4; the required
  version will be incremented to 3.5 soon.

Assorted changes
~~~~~~~~~~~~~~~~

* 750d88d: Errors from predefined exceptions like BadRequest("...") are now
  sent with their text message in the diagnostic payload
* 3c7635f: Examples modernized
* 97fc5f7: Multicast handling changed (but is still not fully supported)
* 933f2b1: Added support for the  No-Response option (RFC7967)
* baa84ee: V4MAPPED addresses are now properly displayed as IPv4 addresses

Tests
~~~~~

* Test suite is now run at Gitlab, and coverage reported
* b2396bf: Test suite probes for usable hostnames for localhost
* b4c5b1d: Allow running tests with a limited set of extras installed
* General improvements on coverage



Version 0.3
-----------

Features
~~~~~~~~

* 4d07615: ICMP errors are handled
* 1b61a29: Accept 'fe80::...%eth0' style addresses
* 3c0120a: Observations provide modern ``async for`` interface
* 4e4ff7c: New demo: file server
* ef2e45e, 991098b, 684ccdd: Messages can be constructed with options, 
  modified copies can be created with the ``.copy`` method, and default codes
  are provided
* 08845f2: Request objects have ``.response_nonraising`` and
  ``.response_raising`` interfaces for easier error handling
* ab5b88a, c49b5c8: Sites can be nested by adding them to an existing site,
  catch-all resources can be created by subclassing PathCapable

Possibly breaking changes
~~~~~~~~~~~~~~~~~~~~~~~~~

* ab5b88a: Site nesting means that server resources do not get their original
  Uri-Path any more
* bc76a7c: Location-{Path,Query} were opaque (bytes) objects instead of
  strings; distinction between accidental and intentional opaque options is
  now clarified

Small features
~~~~~~~~~~~~~~

* 2bb645e: set_request_uri allows URI parsing without sending Uri-Host
* e6b4839: Take block1.size_exponent as a sizing hint when sending block1 data
* 9eafd41: Allow passing in a loop into context creation
* 9ae5bdf: ObservableResource: Add update_observation_count
* c9f21a6: Stop client-side observations when unused
* dd46682: Drop dependency on obscure built-in IN module
* a18c067: Add numbers from draft-ietf-core-etch-04
* fabcfd5: .well-known/core supports filtering

Internals
~~~~~~~~~

* f968d3a: All low-level networking is now done in aiocoap.transports; it's not
  really hotpluggable yet and only UDPv6 (with implicit v4 support) is
  implemented, but an extension point for alternative transports.
* bde8c42: recvmsg is used instead of recvfrom, requiring some asyncio hacks

Package management
~~~~~~~~~~~~~~~~~~

* 01f7232, 0a9d03c: aiocoap-client and -proxy are entry points
* 0e4389c: Establish an extra requirement for LinkHeader
