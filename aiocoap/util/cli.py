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

import argparse
import sys
import logging
import asyncio
import signal

from ..util.asyncio import py38args

class ActionNoYes(argparse.Action):
    """Simple action that automatically manages --{,no-}something style options"""
    # adapted from Omnifarious's code on
    # https://stackoverflow.com/questions/9234258/in-python-argparse-is-it-possible-to-have-paired-no-something-something-arg#9236426
    def __init__(self, option_strings, dest, default=True, required=False, help=None):
        assert len(option_strings) == 1, "ActionNoYes takes only one option name"
        assert option_strings[0].startswith('--'), "ActionNoYes options must start with --"
        super().__init__(['--' + option_strings[0][2:], '--no-' + option_strings[0][2:]], dest, nargs=0, const=None, default=default, required=required, help=help)
    def __call__(self, parser, namespace, values, option_string=None):
        if option_string.startswith('--no-'):
            setattr(namespace, self.dest, False)
        else:
            setattr(namespace, self.dest, True)

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

    Two usage patterns for this are supported:

    * Outside of an async context, run run ``MyClass.sync_main()``, typically
      in the program's ``if __name__ == "__main__":`` section.

      In this mode, the loop that is started is configured to safely shut down
      the loop when SIGINT is received.

    * To run a subclass of this in an existing loop, start it with
      ``MyClass(...)`` (possibly passing in the loop to run it on if not already
      in an async context), and then awaiting its ``.initializing`` future. To
      stop it, await its ``.shutdown()`` method.

      Note that with this usage pattern, the :meth:`.stop()` method has no
      effect; servers that ``.stop()`` themselves need to signal their desire
      to be shut down through other channels (but that is an atypical case).
    """

    def __init__(self, *args, **kwargs):
        loop = kwargs.pop('loop', None)
        if loop is None:
            loop = asyncio.get_running_loop()
        self.__exitcode = loop.create_future()
        self.initializing = loop.create_task(
                self.start(*args, **kwargs),
                **py38args(name="Initialization of %r" % (self,))
                )

    def stop(self, exitcode):
        """Stop the operation (and exit sync_main) at the next convenience."""
        self.__exitcode.set_result(exitcode)

    @classmethod
    async def _async_main(cls, *args, **kwargs):
        """Run the application in an AsyncIO main loop, shutting down cleanly
        on keyboard interrupt.

        This is not exposed publicly as it messes with the loop, and we only do
        that with loops created in sync_main.
        """
        main = cls(*args, **kwargs)

        try:
            asyncio.get_running_loop().add_signal_handler(
                    signal.SIGTERM,
                    lambda: main.__exitcode.set_result(143),
                    )
        except NotImplementedError:
            # Impossible on win32 -- just won't make that clean of a shutdown.
            pass

        try:
            await main.initializing
            # This is the time when we'd signal setup completion by the parent
            # exiting in case of a daemon setup, or to any other process
            # management.
            logging.info("Application ready.")
            # Common options are 143 or 0
            # (<https://github.com/go-task/task/issues/75#issuecomment-339466142> and
            # <https://unix.stackexchange.com/questions/10231/when-does-the-system-send-a-sigterm-to-a-process>)
            exitcode = await main.__exitcode
        except KeyboardInterrupt:
            logging.info("Keyboard interupt received, shutting down")
            sys.exit(3)
        else:
            sys.exit(exitcode)
        finally:
            if main.initializing.done() and main.initializing.exception():
                # The exception if initializing is what we are just watching
                # fly by. No need to trigger it again, and running shutdown
                # would be even weirder.
                pass
            else:
                # May be done, then it's a no-op, or we might have received a
                # signal during startup in which case we better fetch the
                # result and shut down cleanly again
                await main.initializing

                # And no matter whether that happened during initialization
                # (which now has finished) or due to a regular signal...
                await main.shutdown()

    @classmethod
    def sync_main(cls, *args, **kwargs):
        """Run the application in an AsyncIO main loop, shutting down cleanly
        on keyboard interrupt."""
        asyncio.run(cls._async_main(*args, **kwargs))
