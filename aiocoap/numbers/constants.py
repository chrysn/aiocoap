# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Constants either defined in the CoAP protocol (often default values for lack
of ways to determine eg. the estimated round trip time). Some parameters are
invented here for practical purposes of the implementation (eg.
DEFAULT_BLOCK_SIZE_EXP, EMPTY_ACK_DELAY)."""

COAP_PORT = 5683
"""The IANA-assigned standard port for COAP services."""

COAPS_PORT = 5684

MCAST_IPV4_ALLCOAPNODES = "224.0.1.187"
MCAST_IPV6_LINKLOCAL_ALLNODES = "ff02::1"
MCAST_IPV6_LINKLOCAL_ALLCOAPNODES = "ff02::fd"
MCAST_IPV6_SITELOCAL_ALLNODES = "ff05::1"
MCAST_IPV6_SITELOCAL_ALLCOAPNODES = "ff05::fd"
MCAST_IPV6_ALL = (
      MCAST_IPV6_LINKLOCAL_ALLNODES,
      MCAST_IPV6_LINKLOCAL_ALLCOAPNODES,
      MCAST_IPV6_SITELOCAL_ALLNODES,
      MCAST_IPV6_SITELOCAL_ALLCOAPNODES,
      )

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | ACK_TIMEOUT       | 2 seconds     |
#   | ACK_RANDOM_FACTOR | 1.5           |
#   | MAX_RETRANSMIT    | 4             |
#   | NSTART            | 1             |
#   | DEFAULT_LEISURE   | 5 seconds     |
#   | PROBING_RATE      | 1 Byte/second |
#   +-------------------+---------------+

ACK_TIMEOUT = 2.0
"""The time, in seconds, to wait for an acknowledgement of a
confirmable message. The inter-transmission time doubles
for each retransmission."""

ACK_RANDOM_FACTOR = 1.5
"""Timeout multiplier for anti-synchronization."""

MAX_RETRANSMIT = 4
"""The number of retransmissions of confirmable messages to
non-multicast endpoints before the infrastructure assumes no
acknowledgement will be received."""

NSTART = 1
"""Maximum number of simultaneous outstanding interactions
   that endpoint maintains to a given server (including proxies)"""

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | MAX_TRANSMIT_SPAN |          45 s |
#   | MAX_TRANSMIT_WAIT |          93 s |
#   | MAX_LATENCY       |         100 s |
#   | PROCESSING_DELAY  |           2 s |
#   | MAX_RTT           |         202 s |
#   | EXCHANGE_LIFETIME |         247 s |
#   | NON_LIFETIME      |         145 s |
#   +-------------------+---------------+

MAX_TRANSMIT_SPAN = ACK_TIMEOUT * (2 ** MAX_RETRANSMIT - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to its last retransmission."""

MAX_TRANSMIT_WAIT = ACK_TIMEOUT * (2 ** (MAX_RETRANSMIT + 1) - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to the time when the sender gives up on
receiving an acknowledgement or reset."""

MAX_LATENCY = 100.0
"""Maximum time a datagram is expected to take from the start
of its transmission to the completion of its reception."""

PROCESSING_DELAY = ACK_TIMEOUT
""""Time a node takes to turn around a
confirmable message into an acknowledgement."""

MAX_RTT = 2 * MAX_LATENCY + PROCESSING_DELAY
"""Maximum round-trip time."""

EXCHANGE_LIFETIME = MAX_TRANSMIT_SPAN + MAX_RTT
"""time from starting to send a confirmable message to the time when an
acknowledgement is no longer expected, i.e. message layer information about the
message exchange can be purged"""

DEFAULT_BLOCK_SIZE_EXP = 6 # maximum block size 1024
"""Default size exponent for blockwise transfers."""

EMPTY_ACK_DELAY = 0.1
"""After this time protocol sends empty ACK, and separate response"""

REQUEST_TIMEOUT = MAX_TRANSMIT_WAIT
"""Time after which server assumes it won't receive any answer.
   It is not defined by IETF documents.
   For human-operated devices it might be preferable to set some small value
   (for example 10 seconds)
   For M2M it's application dependent."""

DEFAULT_LEISURE = 5

MULTICAST_REQUEST_TIMEOUT = REQUEST_TIMEOUT + DEFAULT_LEISURE

__all__ = [k for k in dir() if not k.startswith('_')]
