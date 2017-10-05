Guided Tour through aiocoap
===========================

This page gets you started on the concepts used in aiocoap; it will assume
rough familiarity with what CoAP is, and a working knowledge of Python
development, but introduce you to asynchronous programming and explain some
CoAP concepts along with the aiocoap API.

If you are already familiar with asynchronous programming and/or some other
concepts involved, or if you prefer reading code to reading tutorials, you
might want to go after the :doc:`examples` instead.

First, some tools
-----------------

Before we get into programming, let's establish tools with which we can probe a
server, and a server itself. If you have not done it already,
:doc:`install aiocoap for development<installation>`.

Start off with the sample server by running the following in a terminal inside
the aiocoap directory::

    $ ./server.py

.. note:: The ``$`` sign indicates the prompt; you enter everything after it in
    a terminal shell. Lines not starting with a dollar sign are the program
    output, if any. Later on, we'll see lines starting with ``>>>``; those are
    run inside a Python interpreter.

    I recommend that you use the IPython_ interpreter. One useful feature for
    following through this tutorial is that you can copy full lines (including
    any ``>>>`` parts) to the clipboard and use the ``%paste`` IPython command
    to run it, taking care of indentation etc.

This has started a CoAP server with some demo content, and keeps running until
you terminate it with Ctrl-C.

In a separate terminal, use :doc:`the aiocoap-client tool <tools>` to send a
GET request to the server::

    $ ./aiocoap-client coap://localhost/.well-known/core
    </time>; obs, </.well-known/core>; ct=40, </other/separate>, </other/block>

The address we're using here is a resource on the local machine (``localhost``)
at the well-known location ``.well-known/core``, which in CoAP is the go-to
location if you don't know anything about the paths on the server beforehand.
It tells that there is a resource at the path ``/time`` that has the ``obs``\
ervable attribute, a resource at the path ``/.well-known/core``, and two more
at ``/other/separate`` and ``/other/block``.

.. note:: Getting "5.00 Internal Server Error" instead? Install the
    `link_header module`_ and restart the server, or trust me that the output
    would look like that if it were installed and proceed.

.. _`link_header module`: https://pypi.python.org/pypi/LinkHeader

.. note:: There can be a "(No newline at end of message)" line below your
    output. This just makes sure your prompt does not start in the middle of
    the screen. I'll just ignore that.

Let's see what ``/time`` gives us::

    $ ./aiocoap-client coap://localhost/time
    2016-12-07 10:08

The response should have arrived immediately: The client sent a message to the
server in which it requested the resource at ``/time``, and the server could
right away send a message back. In contrast, ``/other/separate`` is slower::

    $ ./aiocoap-client coap://localhost/others/separate
    Three rings for the elven kings [abbreviated]

The response to this message comes back with a delay. Here, it is simulated by
the server; in real-life situations, this delay can stem from network latency,
servers waiting for some sensor to read out a value, slow hard drives etc.

A request
---------

In order to run a similar request programmatically, we'll need a request
message::

    >>> from aiocoap import *
    >>> msg = Message(code=GET, uri="coap://localhost/other/separate")
    >>> print(msg)
    <aiocoap.Message at 0x0123deadbeef: None GET (ID None, token b'') remote None, 2 option(s)>

The message consists of several parts. The non-optional ones are largely
handled by aiocoap (message type, ID, token and remote are all None or empty
here and will be populated when the message is sent). The options are roughly
equivalent to what you might know as HTTP headers::

    >>> msg.opt
    <aiocoap.options.Options at 0x0123deadbef0: URI_HOST: localhost, URI_PATH: other / separate>

You might have noticed that the Uri-Path option has whitespace around the
slash. This is because paths in CoAP are not a structured byte string with
slashes in it (as they are in HTTP), but actually repeated options of a (UTF-8)
string, which are represented as a tuple in Python::

    >>> msg.opt.uri_path
    ('other', 'separate')

Now to send that network as a request over the network, we'll need a network
protocol object. That has a request method, and can give a response (bear with
me, these examples don't actually work)::

    >>> protocol.request(msg).response
    <Future pending cb=[Request._response_cancellation_handler()]>

That is obviously not a proper response -- yet. If the protocol returned a
finished response, the program couldn't do any work in the meantime. Because a
Future is returned, the user can start other requests in parallel, or do other
processing in the meantime. For now, all we want is to wait until the response
is ready::

    >>> await protocol.request(msg).response
    <aiocoap.Message at 0x0123deadbef1: Type.CON 2.05 Content (ID 51187, token b'\x00\x00\x81\x99') remote <UDP6EndpointAddress [::ffff:127.0.0.1]:5683 with local address>, 186 byte(s) payload>

Here, we have a successful message ("2.05 Content" is the rough equivalent of
HTTP's "200 OK", and the 186 bytes of payload look promising). Until we can
dissect that, we'll have to get those asynchronous things to work properly,
though.


Asynchronous operation
----------------------

The interactive Python shell does not work in an asynchronous fashion (`yet?`_)
-- it follows a strict "read, evaluate, print" loop (REPL), similar to how a
Python program as a whole is executed. To launch asynchronous processing, we'll
use the following shorthand::

    >>> import asyncio
    >>> run = asyncio.get_event_loop().run_until_complete

With that, we can run asynchronous functions; note that any function that
``await``\ s anything is itself asynchronous and has to be declared
accordingly. Now we can run what did not work before::

    >>> async def main():
    ...     protocol = await Context.create_client_context()
    ...     msg = Message(code=GET, uri="coap://localhost/other/separate")
    ...     response = await protocol.request(msg).response
    ...     print(response)
    >>> run(main())
    <aiocoap.Message at 0x0123deadbef1: Type.CON 2.05 Content (ID 51187, token b'\x00\x00\x81\x99') remote <UDP6EndpointAddress [::ffff:127.0.0.1]:5683 with local address>, 186 byte(s) payload>

That's better!

(Now the ``protocol`` object could also be created. That doesn't actually take
long time, but could, depending on the operating system).


The response
------------

To dissect the response, let's make sure we have it available::

    >>> protocol = run(Context.create_client_context())
    >>> msg = Message(code=GET, uri="coap://localhost/other/separate")
    >>> response = run(protocol.request(msg).response)
    >>> print(response)
    <aiocoap.Message at 0x0123deadbef1: Type.CON 2.05 Content (ID 51187, token b'\x00\x00\x81\x99') remote <UDP6EndpointAddress [::ffff:127.0.0.1]:5683 with local address>, 186 byte(s) payload>

The response obtained in the main function is a message like the request
message, just that it has a different code (2.05 is of the successful 2.00
group), incidentally no options (because it's a very simple server), and actual
data.

The response code is represented in Python by an enum with some utility
functions; the remote address (actually remote-local address pair) is an object
too::

    >>> response.code
    <Successful Response Code 69 "2.05 Content">
    >>> response.code.is_successful()
    True
    >>> response.remote.hostinfo
    '[::ffff:127.0.0.1]'
    >>> response.remote.is_multicast
    False

The actual response message, the body, or the payload of the response, is
accessible in the payload property, and is always a bytestring::

    >>> response.payload
    b'Three rings for the elven kings [ abbreviated ]'

aiocoap does not yet provide utilities to parse the message according to its
content format (which would be accessed as ``response.opt.content_format`` and
is numeric in CoAP).


.. topic:: More asynchronous fun

    The other examples don't show simultaneous requests in flight, so let's
    have one with parallel requests:

        >>> async def main():
        ...     responses = [
        ...         protocol.request(Message(code=GET, uri=u)).response
        ...         for u
        ...         in ("coap://localhost/time", "coap://vs0.inf.ethz.ch/obs", "coap://coap.me/test")
        ...     ]
        ...     for f in asyncio.as_completed(responses):
        ...         response = await f
        ...         print("Response from {}: {}".format(response.get_request_uri(), response.payload))
        >>> run(main())
        Response from coap://localhost/time: b'2016-12-07 18:16'
        Response from coap://vs0.inf.ethz.ch/obs: b'18:16:11'
        Response from coap://coap.me/test: b'welcome to the ETSI plugtest! last change: 2016-12-06 16:02:33 UTC'

   This also shows that the response messages do keep some information of their
   original request (in particular, the request URI) with them to ease further
   parsing.

..
    The server side
    ---------------

    WIP

This is currently the end of the guided tour; see the :mod:`aiocoap.resource`
documentation for the server side until the tour covers that too.is complete.


.. _IPython: http://ipython.org/
.. _`yet?`: https://github.com/ipython/ipython/issues/9166
