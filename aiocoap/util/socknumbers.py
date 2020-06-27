# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

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
"""

import sys

try:
    from socket import IPV6_PKTINFO, IPV6_RECVPKTINFO
except ImportError:
    if sys.platform == 'linux':
        # Not sure if here are any Linux builds at all where this is
        # unavailable
        IPV6_PKTINFO = 50
        IPv6_RECVPKTINFO = 49
    elif sys.platform == 'darwin':
        # when __APPLE_USE_RFC_3542 is defined / as would be when
        # https://bugs.python.org/issue35569 is fixed
        IPV6_PKTINFO = 46
        IPV6_RECVPKTINFO = 61
    # Not attempting to make any guesses for other platforms; the udp6 module
    # will fail to import where it needs the specifics

try:
    from IN import IPV6_RECVERR, IP_RECVERR
except ImportError:
    if sys.platform == 'linux':
        IPV6_RECVERR = 25
        IP_RECVERR = 11

# for https://bitbucket.org/pypy/pypy/issues/2648/
try:
    from socket import MSG_ERRQUEUE
except ImportError:
    if sys.platform == 'linux':
        MSG_ERRQUEUE = 8192

HAS_RECVERR = 'IP_RECVERR' in locals() and 'MSG_ERRQUEUE' in locals()
"""Indicates whether the discovered constants indicate that the Linux
`setsockopt(IPV6, RECVERR)` / `recvmsg(..., MSG_ERRQUEUE)` mechanism is
available"""
