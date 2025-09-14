# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module contains helpers that inspect available modules and platform
specifics to give sane values to aiocoap defaults.

All of this should eventually overridable by other libraries wrapping/using
aiocoap and by applications using aiocoap; however, these overrides do not
happen in the defaults module but where these values are actually accessed, so
this module is considered internal to aiocoap and not part of the API.

The ``_missing_modules`` functions are helpers for inspecting what is
reasonable to expect to work. They can influence default values, but should not
be used in the rest of the code for feature checking (just raise the
ImportErrors) unless it's directly user-visible ("You configured OSCORE key
material, but OSCORE needs the following unavailable modules") or in the test
suite to decide which tests to skip.
"""

import os
import socket
import sys
import warnings

try:
    import pyodide  # noqa: F401
    import js  # noqa: F401
except ImportError:
    is_pyodide = False
else:
    is_pyodide = True


def get_default_clienttransports(*, loop=None, use_env=True):
    """Return a list of transports that should be connected when a client
    context is created.

    If an explicit ``AIOCOAP_CLIENT_TRANSPORT`` environment variable is set, it
    is read as a colon separated list of transport names.

    By default, a DTLS mechanism will be picked if the required modules are
    available, and a UDP transport will be selected depending on whether the
    full udp6 transport is known to work.
    """

    if use_env and "AIOCOAP_CLIENT_TRANSPORT" in os.environ:
        yield from os.environ["AIOCOAP_CLIENT_TRANSPORT"].split(":")
        return

    if not oscore_missing_modules():
        yield "oscore"

    if not is_pyodide:
        # There, those would just raise NotImplementedError all over the place

        if not dtls_missing_modules():
            yield "tinydtls"

        yield "tcpclient"
        yield "tlsclient"

    if not ws_missing_modules():
        yield "ws"

    if is_pyodide:
        # There, the remaining ones would just raise NotImplementedError all over the place
        return

    if sys.platform != "linux":
        # udp6 was never reported to work on anything but linux; would happily
        # add more platforms.
        yield "simple6"
        return

    # on android it seems that it's only the AI_V4MAPPED that causes trouble,
    # that should be managable in udp6 too.
    yield "udp6"
    return


def get_default_servertransports(*, loop=None, use_env=True):
    """Return a list of transports that should be connected when a server
    context is created.

    If an explicit ``AIOCOAP_SERVER_TRANSPORT`` environment variable is set, it
    is read as a colon separated list of transport names.

    By default, a DTLS mechanism will be picked if the required modules are
    available, and a UDP transport will be selected depending on whether the
    full udp6 transport is known to work. Both a simple6 and a simplesocketserver
    will be selected when udp6 is not available, and the simple6 will be used
    for any outgoing requests, which the simplesocketserver could serve but is worse
    at.
    """

    if use_env and "AIOCOAP_SERVER_TRANSPORT" in os.environ:
        yield from os.environ["AIOCOAP_SERVER_TRANSPORT"].split(":")
        return

    if not oscore_missing_modules():
        yield "oscore"

    if not is_pyodide:
        # There, those would just raise NotImplementedError all over the place
        if not dtls_missing_modules():
            if "AIOCOAP_DTLSSERVER_ENABLED" in os.environ:
                yield "tinydtls_server"
            yield "tinydtls"

        yield "tcpserver"
        yield "tcpclient"
        yield "tlsserver"
        yield "tlsclient"

    if not ws_missing_modules():
        yield "ws"

    if is_pyodide:
        # There, the remaining ones would just raise NotImplementedError all over the place
        return

    if sys.platform != "linux":
        # udp6 was never reported to work on anything but linux; would happily
        # add more platforms.
        yield "simple6"
        yield "simplesocketserver"
        return

    # on android it seems that it's only the AI_V4MAPPED that causes trouble,
    # that should be managable in udp6 too.
    yield "udp6"
    return


def has_reuse_port(*, use_env=True):
    """Return true if the platform indicates support for SO_REUSEPORT.

    Can be overridden by explicitly setting ``AIOCOAP_REUSE_PORT`` to 1 or
    0."""

    if use_env and os.environ.get("AIOCOAP_REUSE_PORT"):
        return bool(int(os.environ["AIOCOAP_REUSE_PORT"]))

    return hasattr(socket, "SO_REUSEPORT")


def use_ai_v4mapped_emulation():
    """This used to indicate when ai_v4mapped emulation was used. Given it is
    not used at all any more, the function is deprecated."""
    warnings.warn(
        "AI_V4MAPPED emulation is not used any more at all", warnings.DeprecationWarning
    )
    return False


# FIXME: If there were a way to check for the extras defined in setup.py, or to link these lists to what is descibed there, that'd be great.


def dtls_missing_modules():
    """Return a list of modules that are missing in order to use the DTLS
    transport, or a false value if everything is present"""

    missing = []

    try:
        from DTLSSocket import dtls  # noqa: F401
    except ImportError:
        missing.append("DTLSSocket")

    return missing


def oscore_missing_modules():
    """Return a list of modules that are missing in order to use OSCORE, or a
    false value if everything is present"""
    missing = []
    try:
        import cbor2  # noqa: F401
    except ImportError:
        missing.append("cbor2")
    try:
        import cryptography  # noqa: F401
        import cryptography.exceptions
    except ImportError:
        missing.append("cryptography")
    else:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESCCM

            AESCCM(b"x" * 16, 8)
        except (cryptography.exceptions.UnsupportedAlgorithm, ImportError):
            missing.append("a version of OpenSSL that supports AES-CCM")
    try:
        import filelock  # noqa: F401
    except ImportError:
        missing.append("filelock")

    try:
        import ge25519  # noqa: F401
    except ImportError:
        missing.append("ge25519")

    try:
        import lakers  # noqa: F401
    except ImportError:
        missing.append("lakers-python")

    return missing


def ws_missing_modules():
    """Return a list of modules that are missing in order to user CoAP-over-WS,
    or a false value if everything is present"""

    if is_pyodide:
        return []

    missing = []
    try:
        import websockets  # noqa: F401
    except ImportError:
        missing.append("websockets")

    return missing


def linkheader_missing_modules():
    """Return a list of moudles that are missing in order to use link_header
    functionaity (eg. running a resource directory), of a false value if
    everything is present."""
    missing = []
    # The link_header module is now provided in-tree
    return missing


def prettyprint_missing_modules():
    """Return a list of modules that are missing in order to use pretty
    printing (ie. full aiocoap-client)"""
    missing = []
    missing.extend(linkheader_missing_modules())
    try:
        import cbor2  # noqa: F401
    except ImportError:
        missing.append("cbor2")
    try:
        import pygments  # noqa: F401
    except ImportError:
        missing.append("pygments")
    try:
        import cbor_diag  # noqa: F401
    except ImportError:
        missing.append("cbor-diag")
    # explicitly not covering colorlog: They are bundled to keep the number of
    # externally visible optional dependency groups managable, but the things
    # that depend on `prettyprint_missing_modules` work no matter whether
    # colorlog is in or not.
    return missing


def log_secret(secret):
    """Wrapper around secret values that go into log output.

    Unless AIOCOAP_REVEAL_KEYS is set accordingly, this ignores the input and
    just produces redacted response."""
    return "[redacted]"


if os.environ.get("AIOCOAP_REVEAL_KEYS") == "show secrets in logs":
    if os.access(__file__, mode=os.W_OK):

        def log_secret(secret):
            return secret
    else:
        raise RuntimeError(
            "aiocoap was requested to reveal keys in log files, but aiocoap installation is not writable by user."
        )

missing_module_functions = {
    "dtls": dtls_missing_modules,
    "oscore": oscore_missing_modules,
    "linkheader": linkheader_missing_modules,
    "prettyprint": prettyprint_missing_modules,
    "ws": ws_missing_modules,
}

__all__ = [
    "get_default_clienttransports",
    "get_default_servertransports",
    "has_reuse_port",
    "dtls_missing_modules",
    "oscore_missing_modules",
    "ws_missing_modules",
    "linkheader_missing_modules",
    "prettyprint_missing_modules",
    "missing_module_functions",
]
