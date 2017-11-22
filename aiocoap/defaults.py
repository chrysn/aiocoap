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

The ``_missing_modules`` functions are helpers for inspecting what is
reasonable to expect to work. They can influence default values, but should not
be used in the rest of the code for feature checking (just raise the
ImportErrors) unless it's directly user-visible ("You configured OSCORE key
material, but OSCORE needs the following unavailable modules") or in the test
suite to decide which tests to skip.
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
        yield from os.environ['AIOCOAP_CLIENT_TRANSPORT'].split(':')
        return

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

def get_default_servertransports(*, loop=None):
    """Return a list of transports that should be connected when a server
    context is created.

    If an explicit ``AIOCOAP_SERVER_TRANSPORT`` environment variable is set, it
    is read as a colon separated list of transport names.

    By default, a DTLS mechanism will be picked if the required modules are
    available, and a UDP transport will be selected depending on whether the
    full udp6 transport is known to work. Both a simple6 and a simplesocketserver
    will be selected when udp6 is not available, and the simple6 will be used
    for any outgoing requests, which the simplesocketserver could serve but is worse
    at.
    """

    if 'AIOCOAP_SERVER_TRANSPORT' in os.environ:
        yield from os.environ['AIOCOAP_SERVER_TRANSPORT'].split(':')
        return

    # no server support yet, but doesn't hurt either
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
        yield 'simplesocketserver'
        return

    if loop is None:
        loop = asyncio.get_event_loop()
    # default asyncio works, as does gbulb whose loop is based on asyncio's.
    # uvloop doesn't.
    if not isinstance(loop, asyncio.base_events.BaseEventLoop):
        yield 'simple6'
        yield 'simplesocketserver'
        return

    # on android it seems that it's only the AI_V4MAPPED that causes trouble,
    # that should be managable in udp6 too.
    yield 'udp6'
    return

# FIXME: If there were a way to check for the extras defined in setup.py, or to link these lists to what is descibed there, that'd be great.

def oscore_missing_modules():
    """Return a list of modules that are missing in order to use OSCORE, or a
    false value if everything is present"""
    missing = []
    try:
        import cbor
    except ImportError:
        missing.append('cbor')
    try:
        import hkdf
    except ImportError:
        missing.append('hkdf')
    try:
        import cryptography
    except ImportError:
        missing.append('cryptography')
    return missing

def linkheader_missing_modules():
    """Return a list of moudles that are missing in order to use link_header
    functionaity (eg. running a resource directory), of a false value if
    everything is present."""
    missing = []
    try:
        import link_header
    except ImportError:
        missing.append('link_header')
    return missing
