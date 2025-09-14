# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module contains numeric constants that would be expected in the socket
module, but are not exposed there.

This gathers both socket numbers that can be present in the socket module (eg.
the PKTINFO constants) but are not in some versions (eg. on macOS before
<https://bugs.python.org/issue35569> is fixed) and platform dependent constants
that are not generally available at all (the ERR constants).

Where available, the CPython-private IN module is used to obtain some platform
specific constants.

Any hints on where to get them from in a more reliable way are appreciated;
possible options are parsing C header files (at build time?) or interacting
with shared libraries for obtaining the symbols. The right way would probably
be including them in Python in a "other constants defined on this platform for
sockets" module or dictionary.

As of 2024, most of these are not needed any more; this module will be removed
in favor of directly accessing `socket` constants once Python 3.13 support is
dropped (see [issue 352](https://github.com/chrysn/aiocoap/issues/352)).
"""

import sys

try:
    from socket import IPV6_PKTINFO, IPV6_RECVPKTINFO  # type: ignore
except ImportError:
    if sys.platform == "linux":
        # Not sure if here are any Linux builds at all where this is
        # unavailable
        IPV6_PKTINFO = 50  # type: ignore
        IPv6_RECVPKTINFO = 49  # type: ignore
    elif sys.platform == "darwin":
        # when __APPLE_USE_RFC_3542 is defined / as would be when
        # https://bugs.python.org/issue35569 is fixed
        IPV6_PKTINFO = 46  # type: ignore
        IPV6_RECVPKTINFO = 61  # type: ignore
    # Not attempting to make any guesses for other platforms; the udp6 module
    # will fail to import where it needs the specifics

try:
    from IN import IPV6_RECVERR, IP_RECVERR  # type: ignore
except ImportError:
    if sys.platform == "linux":
        IPV6_RECVERR = 25  # type: ignore
        IP_RECVERR = 11  # type: ignore

# for https://bitbucket.org/pypy/pypy/issues/2648/
try:
    from socket import MSG_ERRQUEUE  # type: ignore
except ImportError:
    if sys.platform == "linux":
        MSG_ERRQUEUE = 8192  # type: ignore

HAS_RECVERR = "IP_RECVERR" in locals() and "MSG_ERRQUEUE" in locals()
"""Indicates whether the discovered constants indicate that the Linux
`setsockopt(IPV6, RECVERR)` / `recvmsg(..., MSG_ERRQUEUE)` mechanism is
available"""
