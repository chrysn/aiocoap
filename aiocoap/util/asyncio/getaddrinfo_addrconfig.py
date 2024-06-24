# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Helper module around getaddrinfo shortcomings"""

import socket
import itertools
import errno


async def getaddrinfo_routechecked(loop, log, host, port):
    """Variant of getaddrinfo that works like AI_ADDRCONFIG should probably work.

    This is not only a workaround for 12377_, but goes beyond it by checking
    routability. Even with 12377 fixed, AI_ADDRCONFIG would just avoid sending
    AAAA requests (if no v6 addresses were available at all). It would still
    not avoid filtering out responses that are just not routable -- the typical
    example being that a host may be in a network with a ULA, so it needs to
    send AAAA requests because they might resolve to the ULA, but if a global
    address comes back, we still don't want that address passed to the
    application.

    The family and flags arguments are not accepted, because they are what is
    being altered (and it'd be hard to tell which combinations would work). It
    roughly behaves as if flags were set to AI_ADDRCONFIG | AI_V4MAPPED, and
    family to AF_INET6. The type and protocol are fixed to SOCK_DGRAM /
    IPPROTO_UDP, because only there we known that connect is side-effect free.

    This function also differs from getaddrinfo in that it returns an
    asynchronous iterator (we don't want to check addresses we don't care
    about), and in that it only returns the sockaddr (because the rest is fixed
    anyway).

    .. _12377: https://sourceware.org/bugzilla/show_bug.cgi?id=12377
    """

    # As an implementation note, we can't go through the AI_V4MAPPED feature,
    # because if we used that, we'd only get V4 responses if there are no V6
    # addresses. As we deliberately want to produce results on V4 addresses
    # when both are provided (conditional on the V6 ones not being routable),
    # we need to convert -- and then the quick way to do things is to use
    # AF_UNSPEC and distinguish later.

    addrinfo = await loop.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP,
        # Still setting that -- it spares us the traffic of pointless requests.
        flags=socket.AI_ADDRCONFIG,
    )

    if any(a[0] not in (socket.AF_INET6, socket.AF_INET) for a in addrinfo):
        log.warning("Addresses outside of INET and INET6 families ignored.")

    v6_addresses = (
        sockaddr for (family, *_, sockaddr) in addrinfo if family == socket.AF_INET6
    )
    # Dress them just as AI_V4MAPPED would do. Note that we can't do (ip, port)
    # instead of sockaddr b/c it's destructured already for the family check,
    # and at that time it may be a different AF with more members.
    v4_addresses = (
        ("::ffff:" + sockaddr[0], sockaddr[1], 0, 0)
        for (family, *_, sockaddr) in addrinfo
        if family == socket.AF_INET
    )

    yielded = 0
    for ip, port, flowinfo, scope_id in itertools.chain(v6_addresses, v4_addresses):
        # Side-step connectivity test when explicitly giving an address. This
        # should be purely a cosmetic change, but given we try not to give IP
        # addresses special treatment over host names, it needs to be done
        # somewhere if we don't want connection attempts to explicit V6
        # addresses to err with "No address information found" on V4-only
        # hosts.
        if ip != host:
            with socket.socket(
                family=socket.AF_INET6, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
            ) as tempsock:
                try:
                    tempsock.connect((ip, port))
                except OSError as e:
                    if e.errno == errno.ENETUNREACH:
                        continue

        yield (ip, port, flowinfo, scope_id)
        yielded += 1

    if not yielded:
        # That's the behavior of getaddrinfo -- not return empty (so we
        # shouldn't return empty just b/c everything was filtered either). Do
        # we need to be any more specific? The gaierror are caught later
        # anyway...
        raise socket.gaierror
