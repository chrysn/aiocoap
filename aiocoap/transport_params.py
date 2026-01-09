# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from dataclasses import dataclass
from typing import Optional, Self

from .util.dataclass_data import LoadStoreClass

# The concrete per-transport data classes are *not* part of the
# aiocoap/transport/ files to avoid eagerly loading them. (And let's see, maybe
# they rackup so many commonalities that it doesn't make sense to have them per
# tranport anyway).


@dataclass
class Udp6Parameters(LoadStoreClass):
    """Parameters for setting up a ``udp6`` transport (see :mod:`..transport_params`
    for context)."""

    # Not managing any details yet; those will come as things are being wired up.


#     ## Address and port to bind to.
#     ##
#     ## The practical value when nothing is given explicitly depends on whether
#     ## a server is run (then it's ``[::]:5683``) or not (then it's effectively
#     ## ``[::]:0``, which binds to an ephemeral port, although the `bind`
#     ## syscall may be elided in that case).
#     bind: Optional[str] = None


@dataclass
class Simple6Parameters(LoadStoreClass):
    """Parameters for setting up a ``simple6`` transport."""


@dataclass
class SimpleSocketServerParameters(LoadStoreClass):
    """Parameters for setting up a ``simplesocketserver`` transport."""


@dataclass
class TinyDTLSParameters(LoadStoreClass):
    """Parameters for setting up a ``tinydtls`` transport."""


@dataclass
class TinyDTLSServerParameters(LoadStoreClass):
    """Parameters for setting up a ``tinydtls_server`` transport."""


@dataclass
class TcpClientParameters(LoadStoreClass):
    """Parameters for setting up a ``tcpclient`` transport."""


@dataclass
class TcpServerParameters(LoadStoreClass):
    """Parameters for setting up a ``tcpserver`` transport."""


@dataclass
class TlsClientParameters(LoadStoreClass):
    """Parameters for setting up a ``tlsclient`` transport."""


@dataclass
class TlsServerParameters(LoadStoreClass):
    """Parameters for setting up a ``tlsserver`` transport."""


@dataclass
class WsParameters(LoadStoreClass):
    """Parameters for setting up a ``ws`` transport."""


@dataclass
class OscoreParameters(LoadStoreClass):
    """Parameters for setting up an ``oscore`` transport."""


@dataclass
class TransportParameters(LoadStoreClass):
    """Parameters that guide which transports are selected and how they are
    configured."""

    @classmethod
    def _compat_create(cls, input: Self | None | dict | list[str]) -> Self:
        """Used to coerce transports= argument of
        ``create_{server,client}_context`` into this type.

        It passes on any instance, loads from a JSON/CBOR/TOML style dict if
        present, selects the default transports when no data is given, and, in
        case of the legacy list-of-strings, sets them up as keys only
        (effectively choosing only those transports without any concrete
        configuration).

        >>> TransportParameters._compat_create(None) == TransportParameters(default_transports=True)
        True
        """

        if isinstance(input, cls):
            return input
        elif input is None:
            return cls(default_transports=True)
        elif isinstance(input, dict):
            return cls.load(input)
        elif isinstance(input, list):
            return cls.load({k: {} for k in input})
        else:
            raise ValueError(
                "Transports needs to bei either TransportParameters, or a dict that can be loaded as one, or None, or (deprecated) a list of transport names."
            )

    ## If True, in any place it applies, parameters for server operation are
    ## set. (For example, the UDP and TCP ports bind to the default port rather
    ## than an ephemeral port, and the default transports selection may be
    ## different).
    ##
    ## Leaving this unset allows the parameters to be set when creating the
    ## context.
    is_server: Optional[bool] = None

    ## If True, all transports that are on by default (or selected by the
    ## environment) are enabled.
    ##
    ## Note that this is False by default: If TransportParameters are given
    ## explicitly (by construction or by loading from JSON/CBOR/TOML style
    ## files), all transports are opt-in, and only when not specifying
    ## anything (or a legacy format) to the Context constructor, this gets set.
    default_transports: bool = False

    udp6: Udp6Parameters | None = None
    simple6: Simple6Parameters | None = None
    simplesocketserver: SimpleSocketServerParameters | None = None
    tinydtls: TinyDTLSParameters | None = None
    tinydtls_server: TinyDTLSServerParameters | None = None
    tcpclient: TcpClientParameters | None = None
    tcpserver: TcpServerParameters | None = None
    tlsclient: TlsClientParameters | None = None
    tlsserver: TlsServerParameters | None = None
    ws: WsParameters | None = None
    oscore: OscoreParameters | None = None
