# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Helpers for creating server-style applications in aiocoap

Note that these are not particular to aiocoap, but are used at different places
in aiocoap and thus shared here."""

import sys
import logging
import asyncio

class AsyncCLIDaemon:
    """Helper for creating daemon-style CLI prorgrams.

    Note that this currently doesn't create a Daemon in the sense of doing a
    daemon-fork; that could be added on demand, though.

    Subclass this and implement the :meth:`start` method as an async
    function; it will be passed all the constructor's arguments.

    When all setup is complete and the program is operational, return from the
    start method.

    Implement the :meth:`shutdown` coroutine and to do cleanup; what actually
    runs your program will, if possible, call that and await its return.

    Typical application for this is running ``MyClass.sync_main()`` in the
    program's ``if __name__ == "__main__":`` section."""

    def __init__(self, *args, **kwargs):
        self.initializing = asyncio.Task(self.start(*args, **kwargs))

    @classmethod
    def sync_main(cls, *args, **kwargs):
        """Run the application in an AsyncIO main loop, shutting down cleanly
        on keyboard interrupt."""
        loop = asyncio.get_event_loop()
        main = cls(*args, **kwargs)
        try:
            loop.run_until_complete(main.initializing)
            # This is the time when we'd signal setup completion by the parent
            # exiting in case of a daemon setup, or to any other process
            # management.
            logging.info("Application ready.")
            loop.run_forever()
        except KeyboardInterrupt:
            logging.info("Keyboard interupt received, shutting down")
            sys.exit(3)
        finally:
            if main.initializing.done() and main.initializing.exception():
                pass # will raise from run_until_complete
            else:
                loop.run_until_complete(main.initializing)
                loop.run_until_complete(main.shutdown())
                loop.stop()
