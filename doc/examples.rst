Usage Examples
==============

These files can serve as reference implementations for a simplistic server and
client. In order to test them, run ``./server.py`` in one terminal, and use
``./clientGET.py`` and ``./clientPUT.py`` to interact with it.

The programs' source code should give you a good starting point to get familiar
with the library if you prefer reading code to reading tutorials. Otherwise,
you might want to have a look at the :doc:`guidedtour`, where the relevant
concepts are introduced and explained step by step.

Unlike the library and its tools, these examples use the modern (Python 3.5 and
later) ``async`` idiom instead of the original asyncio ``yield from``. This is
to align them better with what novice users are expected to learn when
introduced to asynchronous programming in Python.

Client
------

.. literalinclude:: ../clientGET.py
   :language: python
   :linenos:
   :lines: 15-

.. literalinclude:: ../clientPUT.py
   :language: python
   :linenos:
   :lines: 15-

Server
------

.. literalinclude:: ../server.py
   :language: python
   :linenos:
   :lines: 15-
