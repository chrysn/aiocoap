# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""asyncio workarounds"""

import asyncio.events

def cancel_thoroughly(handle):
    """Use this on a (Timer)Handle when you would .cancel() it, just also drop
    the callback and arguments for them to be freed soon."""

    assert isinstance(handle, asyncio.events.Handle)

    handle.cancel()
    handle._args = handle._callback = None
