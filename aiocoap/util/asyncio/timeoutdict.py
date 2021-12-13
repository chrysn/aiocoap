# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

class TimeoutDict:
    """A dict-ish type whose entries live on a timeout; adding and accessing an
    item each refreshes the timeout.

    The timeout is a lower bound; items may live up to twice as long.

    The container is implemented incompletely, with additions made on demand.

    This is not thread safe.
    """

    def __init__(self, timeout: float):
        self.timeout = timeout
        """Timeout set on any access

        This can be changed at runtime, but changes only take effect """

        self._items = {}
        """The actual dictionary"""
        self._recently_accessed = None
        """Items accessed since the timeout last fired"""
        self._timeout = None
        """Canceler for the timeout function"""
        # Note: Without a __del__ implementation that even cancels, the object
        # will be kept alive by the main loop for a timeout

    def __getitem__(self, key):
        result = self._items[key]
        self._accessed(key)
        return result

    def __setitem__(self, key, value):
        self._items[key] = value
        self._accessed(key)

    def _start_over(self):
        """Clear _recently_accessed, set the timeout"""
        self._timeout = asyncio.get_running_loop().call_later(self.timeout, self._tick)
        self._recently_accessed = set()

    def _accessed(self, key):
        """Mark a key as recently accessed"""
        if self._timeout is None:
            self._start_over()
            # No need to add the key, it'll live for this duration anyway
        else:
            self._recently_accessed.add(key)

    def _tick(self):
        self._items = {k: v for (k, v) in self._items.items() if k in self._recently_accessed}
        if self._items:
            self._start_over()
        else:
            self._timeout = None
            self._recently_accessed = None
