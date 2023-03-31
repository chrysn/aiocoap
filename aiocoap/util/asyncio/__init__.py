# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

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
