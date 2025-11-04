# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Test fixtures and decorators that are not test specific"""

import asyncio
import functools
import gc
import inspect
import logging
import os
import pprint
import sys
import unittest
import warnings
import weakref

# time granted to asyncio to receive datagrams sent via loopback, and to close
# connections. if asyncTearDown checks fail erratically, tune this up -- but it
# causes per-fixture delays.
CLEANUPTIME = 0.01

# This is chosen quite loosely to avoid false positives -- but having a timeout
# prevents any test runnier engine (like gitlab runners) from triggering its
# timeout. Thus, the rest of the suite has a chance of running, and we get the
# debug log from the fixture rather than losing the logs to a brutal
# termination.
#
# Tests under system load have shown that TestOSCOREPlugtest.test_005 can
# indeed take quite a while to complete; until I know why, this gives it a
# chance to complete even on occupied systems.
ASYNCTEST_TIMEOUT = 3 * 60


class IsolatedAsyncioTestCase(unittest.IsolatedAsyncioTestCase):
    if sys.version_info < (3, 13):
        # Patching in the 3.13 feature that loop_factory is respected
        def _setupAsyncioRunner(self):
            assert self._asyncioRunner is None, "asyncio runner is already initialized"
            runner = asyncio.Runner(debug=True, loop_factory=self.loop_factory)
            self._asyncioRunner = runner

        loop_factory = None

    if os.environ.get("AIOCOAP_TESTS_LOOP", None) == "uvloop":
        import uvloop as _uvloop

        loop_factory = lambda self: self._uvloop.new_event_loop()
    elif os.environ.get("AIOCOAP_TESTS_LOOP", None) == "glib":
        from gi.events import GLibEventLoopPolicy as _GLibEventLoopPolicy

        loop_factory = lambda self: self._GLibEventLoopPolicy().new_event_loop()


def is_test_successful(testcase):
    """Return true if a current TestCase instancance completed so far without
    raising errors. This is supposed to be used in asyncTearDown handlers on self
    when additional debug information can be shown that would otherwise be
    discarded, or to skip tests during teardown that are bound to fail."""
    return testcase._outcome.success


def no_warnings(function, expected_warnings=None):
    expected_warnings = expected_warnings or []

    def sync_pre(self):
        # assertLogs does not work as assertDoesntLog anyway without major
        # tricking, and it interacts badly with WithLogMonitoring as they both
        # try to change the root logger's level.

        startcount = len(self.handler.list)
        return (startcount,)

    def sync_post(self, pre):
        (startcount,) = pre
        messages = [
            m.getMessage()
            for m in self.handler.list[startcount:]
            if m.levelno >= logging.WARNING
            and "There is no current event loop" not in m.getMessage()
            # Tests are not generally run with precisely known load conditions,
            # and unless in normal operations where this would be an occasional
            # warning, this would trip up our whole test.
            and m.orig_msg != "Executing %s took %.3f seconds"
        ]
        if len(expected_warnings) != len(messages) or not all(
            e == m or (e.endswith("...") and m.startswith(e[:-3]))
            for (e, m) in zip(expected_warnings, messages)
        ):
            self.assertEqual(
                messages,
                expected_warnings,
                "Function %s had unexpected warnings" % function.__name__,
            )

    # Happy function coloring workaround
    if inspect.iscoroutinefunction(function):

        async def wrapped(self, *args, function=function):
            pre = sync_pre(self)
            result = await function(self, *args)
            sync_post(self, pre)
            return result
    else:

        def wrapped(self, *args, function=function):
            pre = sync_pre(self)
            result = function(self, *args)
            sync_post(self, pre)
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


class WithLogMonitoring(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.handler = self.ListHandler()

        logging.root.setLevel(0)
        logging.root.addHandler(self.handler)
        logging.captureWarnings(True)
        warnings.simplefilter("always")

        await super().asyncSetUp()

    async def asyncTearDown(self):
        await super().asyncTearDown()

        logging.root.removeHandler(self.handler)

        complete_log = " Complete log:\n" + "\n".join(
            x.preformatted for x in self.handler.list if x.name != "asyncio"
        )

        # GC runs can emit ResourceWarning, eg. from `sock_finalize`. Let's
        # make sure they don't show up randomly in the next test. (We should
        # still get a hold of them, given that they indicate trouble, but let's
        # not indicate trouble in *unrelated* tests).
        gc.collect()

        if "AIOCOAP_TESTS_SHOWLOG" in os.environ:
            print(complete_log, file=sys.stderr)
            complete_log = "was just printed unconditionally anyway"

    class ListHandler(logging.Handler):
        """Handler that catches log records into a list for later evaluation

        The log records are formatted right away into a .preformatted attribute
        and have their args and exc_info stripped out. This approach retains
        the ability to later filter the messages by logger name or level, but
        drops any references the record might hold to stack frames or other
        passed arguments, as to not interfere with _del_to_be_sure.

        (In regular handlers, these references are not an issue because in
        regular logging the decision whether or not to log is taken right away,
        and maybe then formatting happens, and either way the rest is
        dropped)..
        """

        def __init__(self):
            super().__init__()
            self.list = []
            self.preformatter = logging.Formatter(
                fmt="%(asctime)s:%(levelname)s:%(name)s:%(message)s"
            )

        def emit(self, record):
            record.preformatted = self.preformatter.format(record)

            if not hasattr(record, "orig_msg"):
                # Apparently the same record sometimes gets emitted twice, so
                # let's not overwrite the valuable information in here.
                record.orig_msg = record.msg
            if record.args and not hasattr(record, "style"):
                # Several of the precise_warnings and simiiar uses rely on the
                # ability to match on the message as shown. This mechanism
                # predates the preformatted messages, and is kept as a middle
                # ground. (Matching on something like "Aborting connection: No
                # CSM received" is impossible when the arguments are already
                # thrown away for then it'd be "Aboting connection: %s", but
                # matching into the fully preformatted log record is not ideal
                # either as it effectively means parsing by the above colon
                # format (yes, sub-string matching is probably good enough, but
                # why take chances).
                #
                # The original message is retained for use with cases when it
                # is easier that way.
                record.msg = record.msg % record.args

            record.args = None
            record.exc_info = None
            # The websockets module puts a self-reference into the records
            # through an extra, stripping that to make GC work in
            # _del_to_be_sure
            if hasattr(record, "websocket"):
                del record.websocket

            self.list.append(record)

        def __iter__(self):
            return self.list.__iter__()

    def assertWarned(self, message):
        """Assert that there was a warning with the given message.

        This function also removes the warning from the log, so an enclosing
        @no_warnings (or @precise_warnings) can succeed."""
        for entry in self.handler.list:
            if entry.msg == message and entry.levelno == logging.WARNING:
                self.handler.list.remove(entry)
                break
        else:
            raise AssertionError("Warning not logged: %r" % message)


class Destructing(WithLogMonitoring):
    # Errors produced by this can be quite large, but the truncated version
    # that gets printed when they exceed maxDiff is not useful, so removing any
    # printing limits.
    maxDiff = None

    async def _del_to_be_sure(self, attribute):
        if isinstance(attribute, str):
            getter = lambda self, attribute=attribute: getattr(self, attribute)
            deleter = lambda self, attribute=attribute: delattr(self, attribute)
            label = "self." + attribute
        else:
            getter = attribute["get"]
            deleter = attribute["del"]
            label = attribute["label"]
        weaksurvivor = weakref.ref(getter(self))
        deleter(self)

        if not is_test_successful(self):
            # An error was already logged, and that error's backtrace usually
            # creates references that make any attempt to detect lingering
            # references fuitile. It'll show an error anyway, no use in
            # polluting the logs.
            return

        # let everything that gets async-triggered by close() happen
        await asyncio.sleep(CLEANUPTIME)
        gc.collect()

        def snapshot():
            # This object is created locally and held by the same referrers
            # that also hold the now-recreated survivor.
            #
            # By comparing its referrers to the surviver's referrers, we can
            # filter out this tool's entry in the already hard to read list of
            # objects that kept the survivor alive.
            canary = object()
            survivor = weaksurvivor()
            if survivor is None:
                return None

            all_referrers = gc.get_referrers(survivor)
            canary_referrers = gc.get_referrers(canary)
            if canary_referrers:
                referrers = [r for r in all_referrers if r not in canary_referrers]
                assert len(all_referrers) == len(referrers) + 1, (
                    "Canary to filter out the debugging tool's reference did not work.\nReferrers:\n%s\ncanary_referrers:\n%s"
                    % (pprint.pformat(all_referrers), pprint.pformat(canary_referrers))
                )
            else:
                # There is probably an optimization around that makes the
                # current locals not show up as referrers. It is hoped (and
                # least with the current Python it works) that this also works
                # for the survivor, so it's already not in the list.
                referrers = all_referrers

            def _format_any(frame, survivor_id):
                if str(type(frame)) == "<class 'frame'>":
                    return _format_frame(frame, survivor_id)

                # Kept for future reference only; it appears that at some point
                # up to Python 3.14, get_referrers switched over from producing
                # the dict of an object to the object itself.
                if isinstance(frame, dict):
                    # If it's a __dict__, it'd be really handy to know whose dict that is
                    framerefs = gc.get_referrers(frame)
                    owners = [
                        o for o in framerefs if getattr(o, "__dict__", None) is frame
                    ]
                    if owners:
                        return pprint.pformat(
                            frame
                        ) + "\n  ... which is the __dict__ of %s" % (owners,)

                return pprint.pformat(frame)

            def _format_frame(frame, survivor_id):
                return "%s as %s in %s" % (
                    frame,
                    " / ".join(
                        k for (k, v) in frame.f_locals.items() if id(v) == survivor_id
                    ),
                    frame.f_code,
                )

            # can't use survivor in list comprehension, or it would be moved
            # into a builtins.cell rather than a frame, and that won't spew out
            # the details _format_frame can extract
            survivor_id = id(survivor)
            referrer_strings = [_format_any(x, survivor_id) for x in referrers]
            formatted_survivor = pprint.pformat(vars(survivor))
            return (
                "Survivor found: %r\nReferrers of the survivor:\n*"
                " %s\n\nSurvivor properties: %s"
                % (survivor, "\n* ".join(referrer_strings), formatted_survivor)
            )

        s = snapshot()

        if s is not None:
            original_s = s
            if False:  # enable this if you think that a longer timeout would help
                # this helped finding that timer cancellations don't free the
                # callback, but in general, expect to modify this code if you
                # have to read it; this will need adjustment to your current
                # debugging situation
                logging.root.info("Starting extended grace period")
                for i in range(10):
                    await asyncio.sleep(1)
                    gc.collect()
                    s = snapshot()
                    if s is None:
                        logging.root.info(
                            "Survivor vanished after %r iterations", i + 1
                        )
                        break
                snapshotsmessage = (
                    "Before extended grace period:\n"
                    + original_s
                    + "\n\nAfter extended grace period:\n"
                    + ("the same" if s == original_s else s)
                )
            else:
                snapshotsmessage = s
            errormessage = (
                "Test component %s was not garbage collected.\n\n" % label
                + snapshotsmessage
            )
            self.fail(errormessage)
