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
import inspect
import logging
import pprint
import unittest
import weakref

# time granted to asyncio to receive datagrams sent via loopback, and to close
# connections. if tearDown checks fail erratically, tune this up -- but it
# causes per-fixture delays.
CLEANUPTIME = 0.01

# This is chosen quite losely to avoid false positives -- but having a timeout
# prevents any test runnier engine (like gitlab runners) from triggering its
# timeout. Thus, the rest of the suite has a chance of running, and we get the
# debug log from the fixture rather than losing the logs to a brutal
# termination.
#
# Tests under system load have shown that TestOSCOREPlugtest.test_005 can
# indeed take quite a while to complete; until I know why, this gives it a
# chance to complete even on occupied systems.
ASYNCTEST_TIMEOUT = 3 * 60

def test_is_successful(testcase):
    """Return true if a current TestCase instancance completed so far without
    raising errors. This is supposed to be used in tearDown handlers on self
    when additional debug information can be shown that would otherwise be
    discarded, or to skip tests during teardown that are bound to fail."""
    return not any(e[1] is not None for e in testcase._outcome.errors)

def asynctest(method):
    """Decorator for async WithAsyncLoop fixtures methods that runs them from
    the fixture's loop with a static timeout"""
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        task = asyncio.ensure_future(
                method(self, *args, **kwargs),
                loop=self.loop
            )
        for f in asyncio.as_completed([task], loop=self.loop,
                timeout=ASYNCTEST_TIMEOUT):
            try:
                return self.loop.run_until_complete(f)
            except asyncio.TimeoutError:
                task.cancel()
                # give the task a chance to run finally handlers
                self.loop.run_until_complete(task)
                raise
    return wrapper

def no_warnings(function, expected_warnings=None):
    if inspect.iscoroutinefunction(function):
        raise Exception("no_warnings decorates functions, not coroutines. Put it over @asynctest.")
    expected_warnings = expected_warnings or []
    def wrapped(self, *args, function=function):
        # assertLogs does not work as assertDoesntLog anyway without major
        # tricking, and it interacts badly with WithLogMonitoring as they both
        # try to change the root logger's level.

        startcount = len(self.handler.list)
        result = function(self, *args)
        messages = [m.getMessage() for m in self.handler.list[startcount:] if m.levelno >= logging.WARNING]
        if len(expected_warnings) != len(messages) or not all(
                e == m or (e.endswith('...') and m.startswith(e[:-3]))
                for (e, m)
                in zip(expected_warnings, messages)):
            self.assertEqual(messages, expected_warnings, "Function %s had unexpected warnings"%function.__name__)
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

        formatter = logging.Formatter(fmt='%(asctime)s:%(levelname)s:%(name)s:%(message)s')
        self.assertTrue(test_is_successful(self), "Previous errors were raised."
                " Complete log:\n" + "\n".join(
                formatter.format(x) for x in self.handler.list if x.name != 'asyncio'),
                )

    class ListHandler(logging.Handler):
        def __init__(self):
            self.list = []
        def emit(self, record):
            self.list.append(record)

    def assertWarned(self, message):
        """Assert that there was a warning with the given message.

        This function also removes the warning from the log, so an enclosing
        @no_warnings (or @precise_warnings) can succed."""
        for entry in self.handler.list:
            if entry.msg == message and entry.levelno == logging.WARNING:
                self.handler.list.remove(entry)
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

        def snapshot():
            canary = object()
            survivor = weaksurvivor()
            if survivor is None:
                return None

            all_referrers = gc.get_referrers(survivor)
            canary_referrers = gc.get_referrers(canary)
            referrers = [r for r in all_referrers if r not in canary_referrers]
            assert len(all_referrers) == len(referrers) + 1, "Canary to filter out the debugging tool's reference did not work"

            def _format_frame(frame, survivor_id):
                return "%s as %s in %s" % (
                    frame,
                    " / ".join(k for (k, v) in frame.f_locals.items() if id(v) == survivor_id),
                    frame.f_code)

            # can't use survivor in list comprehension, or it would be moved
            # into a builtins.cell rather than a frame, and that won't spew out
            # the details _format_frame can extract
            survivor_id = id(survivor)
            referrer_strings = [
                    _format_frame(x, survivor_id) if str(type(x)) == "<class 'frame'>" else pprint.pformat(x) for x in
                    referrers]
            formatted_survivor = pprint.pformat(vars(survivor))
            return "Survivor found: %r\nReferrers of the survivor:\n*"\
                   " %s\n\nSurvivor properties: %s" % (
                       survivor,
                       "\n* ".join(referrer_strings),
                        formatted_survivor)

        s = snapshot()

        if not test_is_successful(self):
            # An error was already logged, and that error's backtrace usually
            # creates references that make any attempt to detect lingering
            # references fuitile. It'll show an error anyway, no use in
            # polluting the logs.
            return

        if s is not None:
            original_s = s
            if False: # enable this if you think that a longer timeout would help
                # this helped finding that timer cancellations don't free the
                # callback, but in general, expect to modify this code if you
                # have to read it; this will need adjustment to your current
                # debugging situation
                logging.root.info("Starting extended grace period")
                for i in range(10):
                    self.loop.run_until_complete(asyncio.sleep(1))
                    gc.collect()
                    s = snapshot()
                    if s is None:
                        logging.root.info("Survivor vanished after %r iterations" % i+1)
                        break
                snapshotsmessage = "Before extended grace period:\n" + original_s + "\n\nAfter extended grace period:\n" + ("the same" if s == original_s else s)
            else:
                snapshotsmessage = s
            errormessage = "Protocol %s was not garbage collected.\n\n"%attribute + snapshotsmessage
            self.fail(errormessage)
