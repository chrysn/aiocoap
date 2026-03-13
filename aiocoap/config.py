# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Self

from .util.dataclass_data import LoadStoreClass

# The concrete per-transport data classes are *not* part of the
# aiocoap/transport/ files to avoid eagerly loading them. (And let's see, maybe
# they rackup so many commonalities that it doesn't make sense to have them per
# tranport anyway).


@dataclass
class Udp6Parameters(LoadStoreClass):
    """Parameters for setting up a :mod:`udp6 <aiocoap.transports.udp6>` transport."""

    # Not managing any details yet; those will come as things are being wired up.


#     bind: Optional[str] = None
#     """Address and port to bind to.
#
#     The practical value when nothing is given explicitly depends on whether
#     a server is run (then it's ``[::]:5683``) or not (then it's effectively
#     ``[::]:0``, which binds to an ephemeral port, although the `bind`
#     syscall may be elided in that case)."""


@dataclass
class Simple6Parameters(LoadStoreClass):
    """Parameters for setting up a :mod:`simple6 <aiocoap.transports.simple6>` transport."""


@dataclass
class SimpleSocketServerParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`simplesocketserver <aiocoap.transports.simplesocketserver>` transport."""


@dataclass
class TinyDTLSParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`tinydtls <aiocoap.transports.tinydtls>` transport."""


@dataclass
class TinyDTLSServerParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`tinydtls_server <aiocoap.transports.tinydtls_server>` transport."""


@dataclass
class TcpClientParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`tcpclient <aiocoap.transports.tcpclient>` transport."""


@dataclass
class TcpServerParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`tcpserver <aiocoap.transports.tcpserver>` transport."""


@dataclass
class TlsClientParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`tlsclient <aiocoap.transports.tlsclient>` transport."""


@dataclass
class TlsServerParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`tlsserver <aiocoap.transports.tlsserver>` transport."""


@dataclass
class WsParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`ws <aiocoap.transports.ws>` transport."""


@dataclass
class OscoreParameters(LoadStoreClass):
    """Parameters for setting up an :mod:`oscore <aiocoap.transports.oscore>` transport."""


@dataclass
class SlipmuxDevice(LoadStoreClass):
    """Parameters for a single slipmux device.

    By default, establishes a connection by looking up the name
    case-insensitively in ``/dev/`` (which works for UNIXes), falling back to
    opening the device by its name (which probably works on Windows)"""

    device: Optional[Path] = None
    """Overrides the path at which the device file is expected.

    This can be useful when catering for device path renames, or when devices
    contain characters that are not trivially encoded in the Hostname component
    of a URI."""

    unix_connect: Optional[Path] = None
    """If set, connection is not made through a serial port but rather by
    connecting to a UNIX socket at that file name."""

    unix_listen: Optional[Path] = None
    """If set, connection is not made through a serial port but rather by
    creating and listening at a UNIX socket at that file name."""

    def __post_init__(self):
        if (
            sum(
                f is not None
                for f in (self.device, self.unix_connect, self.unix_listen)
            )
            > 1
        ):
            raise ValueError(
                "Only one (or none) of the 'device', 'unix-connect' and 'unix-listen' fields can be set per device."
            )


@dataclass
class SlipmuxParameters(LoadStoreClass):
    """Parameters for setting up a :mod:`slipmux <aiocoap.transports.slipmux>` transport."""

    devices: dict[str, SlipmuxDevice] = field(default_factory=dict)
    """Details of known slipmux devices.

    The keys are the "devname" part of the ``coap://devname.dev.alt`` origins
    used with slimux.

    Setting an item is done for two practical effects:
        * It allows overriding properties (see :class:`SlipmuxParameters`).
        * When configured as a server, these are the ports that get connected
          at startup.
    """


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

    def _apply_defaults(self):
        """Modifies self to enable all transports from the
        :mod:`aiocoap.defaults` settings (which pulls in environment variables
        and installed modules).

        This only applies any changes if ``.default_transports`` is present. It
        expects ``.is_server`` to be decided already."""

        from . import defaults

        if not self.default_transports:
            return

        if self.is_server:
            transports = defaults.get_default_servertransports()
        else:
            transports = defaults.get_default_clienttransports()

        add_transports = [t for t in transports if getattr(self, t) is None]
        # We don't have good APIs to incrementally load, so we just create
        # something to splice into self
        empty_transports = self.load({k: {} for k in add_transports})
        for t in add_transports:
            setattr(self, t, getattr(empty_transports, t))

    is_server: Optional[bool] = None
    """If True, in any place it applies, parameters for server operation are
    set. (For example, the UDP and TCP ports bind to the default port rather
    than an ephemeral port, and the default transports selection may be
    different).

    Leaving this unset allows the parameters to be set when creating the
    context."""

    default_transports: bool = False
    """If True, all transports that are on by default (or selected by the
    environment) are enabled.

    Note that this is False by default: If TransportParameters are given
    explicitly (by construction or by loading from JSON/CBOR/TOML style files),
    all transports are opt-in, and only when not specifying anything (or a
    legacy format) to the Context constructor, this gets set."""

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
    slipmux: SlipmuxParameters | None = None


@dataclass
class Config(LoadStoreClass):
    """Configuration for aiocoap

    An instance of this type covers aspects of aiocoap's behavior that are
    orthogonal to typical CoAP server or client applications, or for which an
    application would typically only forward configuration settings to."""

    transport: TransportParameters = field(
        default_factory=lambda: TransportParameters._compat_create(None)
    )
