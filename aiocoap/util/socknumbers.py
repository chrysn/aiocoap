# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains numeric constants that would be expected in the socket
module, but are not exposed there.

For some platforms (eg. python up to 3.5 on Linux), there is an IN module that
exposes them; and they are gathered from there.

As a fallback, the numbers are hardcoded. Any hints on where to get them from
are appreciated; possible options are parsing C header files (at build time?)
or interacting with shared libraries for obtaining the symbols. The right way
would probably be including them in Python.
"""

try:
    from IN import IPV6_RECVERR, IP_RECVERR, IPV6_PKTINFO
except ImportError:
    IPV6_RECVERR = 25
    IP_RECVERR = 11
    IPV6_PKTINFO = 50

# for https://bitbucket.org/pypy/pypy/issues/2648/
try:
    from socket import MSG_ERRQUEUE
except ImportError:
    MSG_ERRQUEUE = 8192
