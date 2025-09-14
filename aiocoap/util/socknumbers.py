# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module contains numeric constants that would be expected in the socket
module, but are not exposed there yet.

This module will be removed in favor of directly accessing `socket` constants
once Python 3.13 support is dropped (see
[issue 352](https://github.com/chrysn/aiocoap/issues/352)), with any remnants
(decision on whether the RECVERR mechanism *can* be used) moved into the
defaults module.
"""

import sys

try:
    from socket import IPV6_RECVERR, IP_RECVERR, MSG_ERRQUEUE  # type: ignore
except ImportError:
    if sys.version_info < (3, 14):
        if sys.platform == "linux":
            IPV6_RECVERR = 25  # type: ignore
            IP_RECVERR = 11  # type: ignore
            MSG_ERRQUEUE = 8192  # type: ignore
        # This is not available on other platforms.

HAS_RECVERR = "IP_RECVERR" in locals() and "MSG_ERRQUEUE" in locals()
"""Indicates whether the discovered constants indicate that the Linux
`setsockopt(IPV6, RECVERR)` / `recvmsg(..., MSG_ERRQUEUE)` mechanism is
available"""
