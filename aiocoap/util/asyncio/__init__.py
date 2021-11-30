# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Extensions to asyncio and workarounds around its shortcomings"""

import sys

def py38args(**kwargs):
    """Wrapper around kwargs that replaces them with an empty list for Python
    versions earlier than 3.8.

    This is used to assign a name in asyncio.create_task to pass in a name."""
    if sys.version_info >= (3, 8):
        return kwargs
    else:
        return {}
