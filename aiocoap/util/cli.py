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

    * To run a subclass of this in an existing loop, start it with
      ``MyClass(...)`` (possibly passing in the loop to run it on if not already
      in an async context), and then awaiting its ``.initializing`` future. To
      stop it, await its ``.shutdown()`` method.

      This pattern is going to be deprecated or removed entirely when ported to
      async context managers.
    """

    def __init__(self, *args, **kwargs):
        self.__loop = kwargs.pop('loop', None)
        if self.__loop is None:
            self.__loop = asyncio.get_running_loop()
        self.__exitcode = self.__loop.create_future()
        self.initializing = self.__loop.create_task(self.start(*args, **kwargs))

    def stop(self, exitcode):
        """Stop the operation (and exit sync_main) at the next convenience."""
        self.__exitcode.set_result(exitcode)

    @classmethod
    def sync_main(cls, *args, **kwargs):
        """Run the application in an AsyncIO main loop, shutting down cleanly
        on keyboard interrupt."""
        main = cls(*args, loop=asyncio.new_event_loop(), **kwargs)
        try:
            main.__loop.run_until_complete(main.initializing)
            # This is the time when we'd signal setup completion by the parent
            # exiting in case of a daemon setup, or to any other process
            # management.
            logging.info("Application ready.")
            # Common options are 143 or 0
            # (<https://github.com/go-task/task/issues/75#issuecomment-339466142> and
            # <https://unix.stackexchange.com/questions/10231/when-does-the-system-send-a-sigterm-to-a-process>)
            try:
                main.__loop.add_signal_handler(signal.SIGTERM, lambda: main.__exitcode.set_result(143))
            except NotImplementedError:
                # Impossible on win32 -- just won't make that clean of a shutdown.
                pass
            exitcode = main.__loop.run_until_complete(main.__exitcode)
        except KeyboardInterrupt:
            logging.info("Keyboard interupt received, shutting down")
            sys.exit(3)
        else:
            sys.exit(exitcode)
        finally:
            if main.initializing.done() and main.initializing.exception():
                pass # will raise from run_until_complete
            else:
                main.__loop.run_until_complete(main.initializing)
                main.__loop.run_until_complete(main.shutdown())
                main.__loop.stop()
