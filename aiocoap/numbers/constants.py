# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Constants either defined in the CoAP protocol (often default values for lack
of ways to determine eg. the estimated round trip time). Some parameters are
invented here for practical purposes of the implementation (eg.
DEFAULT_BLOCK_SIZE_EXP, EMPTY_ACK_DELAY)."""

import warnings
import string

COAP_PORT = 5683
"""The IANA-assigned standard port for COAP services."""

COAPS_PORT = 5684

MCAST_IPV4_ALLCOAPNODES = "224.0.1.187"
MCAST_IPV6_LINKLOCAL_ALLNODES = "ff02::1"
MCAST_IPV6_LINKLOCAL_ALLCOAPNODES = "ff02::fd"
MCAST_IPV6_SITELOCAL_ALLNODES = "ff05::1"
MCAST_IPV6_SITELOCAL_ALLCOAPNODES = "ff05::fd"
MCAST_ALL = (
      MCAST_IPV4_ALLCOAPNODES,
      MCAST_IPV6_LINKLOCAL_ALLNODES,
      MCAST_IPV6_LINKLOCAL_ALLCOAPNODES,
      MCAST_IPV6_SITELOCAL_ALLNODES,
      MCAST_IPV6_SITELOCAL_ALLCOAPNODES,
      )

MAX_REGULAR_BLOCK_SIZE_EXP = 6

class TransportTuning:
    """Base parameters that guide CoAP transport behaviors

    The values in here are recommended values, often defaults from RFCs. They
    can be tuned in subclasses (and then passed into a message as
    ``transport_tuning``), although users should be aware that alteing some of
    these can cause the library to behave in ways violating the specification,
    especially with respect to congestion control.
    """

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

    @property
    def MAX_TRANSMIT_SPAN(self):
        """Maximum time from the first transmission
        of a confirmable message to its last retransmission."""
        return self.ACK_TIMEOUT * (2 ** self.MAX_RETRANSMIT - 1) * self.ACK_RANDOM_FACTOR

    @property
    def MAX_TRANSMIT_WAIT(self):
        """Maximum time from the first transmission
        of a confirmable message to the time when the sender gives up on
        receiving an acknowledgement or reset."""
        return self.ACK_TIMEOUT * (2 ** (self.MAX_RETRANSMIT + 1) - 1) * self.ACK_RANDOM_FACTOR

    MAX_LATENCY = 100.0
    """Maximum time a datagram is expected to take from the start
    of its transmission to the completion of its reception."""

    @property
    def PROCESSING_DELAY(self):
        """"Time a node takes to turn around a
        confirmable message into an acknowledgement."""
        return self.ACK_TIMEOUT

    @property
    def MAX_RTT(self):
        """Maximum round-trip time."""
        return 2 * self.MAX_LATENCY + self.PROCESSING_DELAY

    @property
    def EXCHANGE_LIFETIME(self):
        """time from starting to send a confirmable message to the time when an
        acknowledgement is no longer expected, i.e. message layer information about the
        message exchange can be purged"""
        return self.MAX_TRANSMIT_SPAN + self.MAX_RTT

    DEFAULT_BLOCK_SIZE_EXP = MAX_REGULAR_BLOCK_SIZE_EXP
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

    @property
    def MULTICAST_REQUEST_TIMEOUT(self):
        return self.REQUEST_TIMEOUT + self.DEFAULT_LEISURE

    OBSERVATION_RESET_TIME = 128
    """Time in seconds after which the value of the observe field are ignored.

    This number is not explicitly named in RFC7641.
    """

_default_transport_tuning = TransportTuning()
def __getattr__(name):
    if name[0] in string.ascii_uppercase and hasattr(_default_transport_tuning, name):
        warnings.warn(f"{name} is deprecated, use through the message's transport_tuning instead", DeprecationWarning, stacklevel=2)
        return getattr(_default_transport_tuning, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")

SHUTDOWN_TIMEOUT = 3
"""Maximum time, in seconds, for which the process is kept around during shutdown"""

__all__ = [k for k in dir() if not k.startswith('_') and k not in ('warnings', 'strings')]
