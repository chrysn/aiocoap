# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Helper module to work around platform limitations where V6ONLY=0 can be set,
but getaddrinfo can not deal with AI_V4MAPPED; this is currently known to
affect only Android.

The emulation is enabled depending on
:func:`aiocoap.defaults.use_ai_v4mapped_emulation`.

Unless Python is used with optimization enabled, emulation will be run on all
getaddrinfo calls in addition to the regular call, and a warning is shown if
they disagree.

Future development
------------------

It may be that for proper happy-eyeballs support, AI_V4MAPPED is not quite the
right way to go: It will show a mapped address only if there are no V6 results
-- whereas on links without V6 connectivity, one would like to receive both
results and try them in order.
"""

import ipaddress
import socket
import warnings

from ...defaults import use_ai_v4mapped_emulation

async def getaddrinfo(loop, host, port, *, family=0, type=0, proto=0, flags=0):
    """A wrapper around getaddrinfo that soft-implements AI_V4MAPPED on
    platforms that do not have that option, but do actually support dual
    stack."""

    emulation_applies = family == socket.AF_INET6 and flags & socket.AI_V4MAPPED

    use_emulation = use_ai_v4mapped_emulation()

    if not emulation_applies or (not use_emulation and not __debug__):
        return await loop.getaddrinfo(host, port, family=family, type=type, proto=proto, flags=flags)

    emulated = await _emulate(loop, host, port, family=family, type=type, proto=proto, flags=flags)

    if use_emulation:
        if isinstance(emulated, Exception):
            raise emulated
        return emulated

    actual = await _getaddrinfo_nonraising(loop, host, port, family=family, type=type, proto=proto, flags=flags)
    # if actual != emulated:
    #     warnings.warn("Emulation of V4MAPPED addresses is erroneous: System returned %s, emulation returned %s" % (actual, emulated))

    if isinstance(actual, Exception):
        raise actual
    return actual

async def _emulate(loop, host, port, *, family=0, type=0, proto=0, flags=0):
    assert family == socket.AF_INET6
    assert flags & socket.AI_V4MAPPED
    new_flags = flags & ~socket.AI_V4MAPPED

    # Control-flow-by-exception is not a good thing to have, but there's no
    # standard library function for "is this an IPv6 address".
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        is_v4address = False
    else:
        is_v4address = True

    if not is_v4address:
        v6_result = await _getaddrinfo_nonraising(loop, host, port, family=socket.AF_INET6, type=type, proto=proto, flags=new_flags)
    else:
        v6_result = None

    if isinstance(v6_result, list):
        return v6_result

    # This should never hit the "this is a V6 address" case, because those
    # already give a good v6_result
    v4_result = await _getaddrinfo_nonraising(loop, host, port, family=socket.AF_INET, type=type, proto=proto, flags=new_flags)

    if isinstance(v4_result, list):
        return [
                (socket.AF_INET6, type, proto, canonname, ('::ffff:' + sa_ip, sa_port, 0, 0))
                for (_, type, proto, canonname, (sa_ip, sa_port))
                in v4_result
                ]

    assert v6_result is not None, "IPv4 address was not accketed in v4 getaddrinfo"
    raise v6_result

async def _getaddrinfo_nonraising(loop, *args, **kwargs):
    """A version of loop.getaddinfo() that just returns its exception rather than raising it"""
    try:
        return await loop.getaddrinfo(*args, **kwargs)
    except socket.gaierror as e:
        return e
