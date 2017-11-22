Usage Examples
==============

These files can serve as reference implementations for a simplistic server and
client. In order to test them, run ``./server.py`` in one terminal, and use
``./clientGET.py`` and ``./clientPUT.py`` to interact with it.

The programs' source code should give you a good starting point to get familiar
with the library if you prefer reading code to reading tutorials. Otherwise,
you might want to have a look at the :doc:`guidedtour`, where the relevant
concepts are introduced and explained step by step.

.. note:: These example programs are not shipped in library version of aiocoap.
    They are present if you followed the :ref:`installation-development`
    section of the installation instructions; otherwise, you can download them
    from the project website.

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
