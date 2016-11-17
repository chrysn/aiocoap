Usage Examples
==============

In absence of a complete tutorial, these files can serve as reference
implementations for server and client. In order to test them, run
``./server.py`` in one terminal, and use ``./clientGET.py`` and
``./clientPUT.py`` to interact with it.

Unlike the library and its tools, these examples use the modern (Python 3.5 and
later) ``async`` idiom instead of the original asyncio ``yield from``. This is
to align them better with what novice users are expected to learn when
introduced to asynchronous programming in Python.

Client
------

.. literalinclude:: ../clientGET.py
   :language: python
   :linenos:
   :lines: 10-

.. literalinclude:: ../clientPUT.py
   :language: python
   :linenos:
   :lines: 10-

Server
------

.. literalinclude:: ../server.py
   :language: python
   :linenos:
   :lines: 10-
