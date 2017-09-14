# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains helpers that inspect available modules and platform
specifics to give sane values to aiocoap defaults.

All of this should eventually overridable by other libraries wrapping/using
aiocoap and by applications using aiocoap; however, these overrides do not
happen in the defaults module but where these values are actually accessed, so
this module is considered internal to aiocoap and not part of the API.
"""

import os
import sys
import asyncio

def get_default_clienttransports(*, loop=None):
    """Return a list of transports that should be connected when a client
    context is created.

    If an explicit ``AIOCOAP_CLIENT_TRANSPORT`` environment variable is set, it
    is read as a colon separated list of transport names.

    By default, a DTLS mechanism will be picked if the required modules are
    available, and a UDP transport will be selected depending on whether the
    full udp6 transport is known to work.
    """

    if 'AIOCOAP_CLIENT_TRANSPORT' in os.environ:
        return os.environ['AIOCOAP_CLIENT_TRANSPORT'].split(':')

    try:
        from DTLSSocket import dtls
    except ImportError:
        pass
    else:
        yield 'tinydtls'

    if sys.platform != 'linux':
        # udp6 was never reported to work on anything but linux; would happily
        # add more platforms.
        yield 'simple6'
        return

    if loop is None:
        loop = asyncio.get_event_loop()
    # default asyncio works, as does gbulb whose loop is based on asyncio's.
    # uvloop doesn't.
    if not isinstance(loop, asyncio.base_events.BaseEventLoop):
        yield 'simple6'
        return

    # on android it seems that it's only the AI_V4MAPPED that causes trouble,
    # that should be managable in udp6 too.
    yield 'udp6'
    return
