# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Test fixtures and decorators that are not test specific"""

import asyncio
import functools
import gc
import logging
import pprint
import unittest
import weakref

# time granted to asyncio to receive datagrams sent via loopback, and to close
# connections. if tearDown checks fail erratically, tune this up -- but it
# causes per-fixture delays.
CLEANUPTIME = 0.01

def no_warnings(function, expected_warnings=None):
    expected_warnings = expected_warnings or []
    def wrapped(self, *args, function=function):
        # assertLogs does not work as assertDoesntLog anyway without major
        # tricking, and it interacts badly with WithLogMonitoring as they both
        # try to change the root logger's level.

        startcount = len(self.handler)
        result = function(self, *args)
        messages = [m.msg for m in self.handler[startcount:] if m.levelno >= logging.WARNING]
        if len(expected_warnings) != len(messages) or not all(
                e == m or (e.endswith('...') and m.startswith(e[:-3]))
                for (e, m)
                in zip(expected_warnings, messages)):
            self.assertEqual(messages, expected_warnings, "Function %s had unexpected warnings: %s"%(function.__name__, messages))
        return result
    wrapped.__name__ = function.__name__
    wrapped.__doc__ = function.__doc__
    return wrapped

def precise_warnings(expected_warnings):
    """Expect that the expected_warnings list are the very warnings shown
    (no_warnings is a special case with []).

    "precise" is a bit of a misnomer here; the expected warnings may end with
    "..." indicating that the rest of the line may be arbitrary."""
    return functools.partial(no_warnings, expected_warnings=expected_warnings)

class WithLogMonitoring(unittest.TestCase):
    def setUp(self):
        self.handler = self.ListHandler()

        logging.root.setLevel(0)
        logging.root.addHandler(self.handler)

        super(WithLogMonitoring, self).setUp()

    def tearDown(self):
        super(WithLogMonitoring, self).tearDown()

        logging.root.removeHandler(self.handler)
#
#        formatter = logging.Formatter(fmt='%(levelname)s:%(name)s:%(message)s')
#        print("fyi:\n", "\n".join(formatter.format(x) for x in self.handler if x.name != 'asyncio'))

    class ListHandler(logging.Handler, list):
        def emit(self, record):
            self.append(record)

    def assertWarned(self, message):
        """Assert that there was a warning with the given message.

        This function also removes the warning from the log, so an enclosing
        @no_warnings (or @precise_warnings) can succed."""
        for entry in self.handler:
            if entry.msg == message and entry.levelno == logging.WARNING:
                self.handler.remove(entry)
                break
        else:
            raise AssertionError("Warning not logged: %r"%message)

class WithAsyncLoop(unittest.TestCase):
    def setUp(self):
        super(WithAsyncLoop, self).setUp()

        self.loop = asyncio.get_event_loop()

class Destructing(WithLogMonitoring):
    def _del_to_be_sure(self, attribute):
        weaksurvivor = weakref.ref(getattr(self, attribute))
        delattr(self, attribute)
        # let everything that gets async-triggered by close() happen
        self.loop.run_until_complete(asyncio.sleep(CLEANUPTIME))
        gc.collect()
        survivor = weaksurvivor()
        if survivor is not None:
            snapshot = lambda: "Referrers: %s\n\nProperties: %s"%(pprint.pformat(gc.get_referrers(survivor)), pprint.pformat(vars(survivor)))
            snapshot1 = snapshot()
            if False: # enable this if you think that a longer timeout would help
                # this helped finding that timer cancellations don't free the
                # callback, but in general, expect to modify this code if you
                # have to read it; this will need adjustment to your current
                # debugging situation
                logging.root.info("Starting extended grace period")
                for i in range(10):
                    self.loop.run_until_complete(asyncio.sleep(1))
                    del survivor
                    gc.collect()
                    survivor = weaksurvivor()
                    logging.root.info("Now %ds into grace period, survivor is %r"%((i+1)/1, survivor))
                    if survivor is None:
                        break
                snapshot2 = snapshot() if survivor else "no survivor"
                snapshotsmessage = "Before extended grace period:\n" + snapshot1 + "\n\nAfter extended grace period:\n" + snapshot2
            else:
                snapshotsmessage = snapshot1
            formatter = logging.Formatter(fmt='%(levelname)s:%(name)s:%(message)s')
            errormessage = "Protocol %s was not garbage collected.\n\n"%attribute + snapshotsmessage + "\n\nLog of the unit test:\n" + "\n".join(formatter.format(x) for x in self.handler)
            self.fail(errormessage)
