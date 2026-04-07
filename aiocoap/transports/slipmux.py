# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module implements slipmux-03_, with some adjustments regarding URI design
taken from transport-indication_: It chooses the pattern `{NAME}.dev.alt` for
devices named /dev/{NAME}, which are treated case-insensitively.

Usage example
=============

Client with physical hardware
-----------------------------

Assuming you have a constrained device that suports slipmux connected to a PC
as ``/dev/ttyACM0``, you can run::

    $ aiocoap-client coap://ttyacm0.dev.alt/.well-known/core

and interact with resources as found there; no further configuration is needed.

Server with test peer
---------------------

To mock slipmux without a real serial connection, you can configure a slipmux
host name to open up a UNIX socket instead. Write this configuration into
``config-unix-listen.toml``::

    [transport.slipmux.devices]
    my-listener = { unix-listen = "/tmp/coap.socket" }

Then run a server such as the file server::

    $ aiocoap-fileserver --server-config config-unix-listen.toml

You can then run a client such as Jelly intreactively with that server::

    $ cargo install Jelly
    $ Jelly /tmp/coap.socket

Beware that the aiocoap based server needs to be restarted when the client
disconnects (see Caveats below).

Client with test peer
---------------------

You can also run aiocoap as a test client, but as that doesn't take a file name
argument to connect to (because it operates on URIs' host components), some
configuration is necessary. Store this in ``config-unix-connect.toml``::

    [transport.slipmux.devices]
    my-connection = { unix-connect = "/tmp/coap.socket" }

Then run::

    $ aiocoap-client coap://my-connection.dev.alt/.well-known/core --config config-unix-connect.toml

Caveats
=======

While servers do connect automatically to any configured slipmux endpoint, they
do not reconnect automatically when that device goes away or is replaced (as
may happen when resetting a development board, depending on its USB UART
implementation). The same is true for UNIX sockets.

Error handing is generally incomplete when it comes to I/O errors.

This transport is currently not tested automatically, as only the client side
is implemented, with no mechanism for acting on (eg.) a UNIX socket instead.

.. _slipmux-03: https://datatracker.ietf.org/doc/draft-bormann-t2trg-slipmux/03/
.. _transport-indication: https://datatracker.ietf.org/doc/draft-ietf-core-transport-indication

------
"""

from __future__ import annotations

# Implementation experience notes:
#
# * lower/upper in device names is tedious, esp. with defaults such as ttyACM0
# * FCS is very old reference that had no test vectors; single example would be helpful.
# * Ports numbers?

import asyncio
import os
from pathlib import Path
import string
from typing import Optional
import weakref

import serial_asyncio

from .. import Message
from .. import error, interfaces

# circular but allows matching on constants
from . import slipmux

from ..config import TransportParameters, SlipmuxDevice

# from RFC1055
ESC = 0o333
END = 0o300
ESC_END = 0o334
ESC_ESC = 0o335
# but at runtime we need the combined forms
BYTE_ESC = bytes((ESC,))
BYTE_END = bytes((END,))
BYTES_ESC_ESC_END = BYTE_ESC + bytes((ESC_END,))
BYTES_ESC_ESC_ESC = BYTE_ESC + bytes((ESC_ESC,))

# from slipmux draft
HEADER_CONTROL = 0xA9

# from RFC3986
_UNRESERVED = string.ascii_lowercase + string.digits + "-._~"

# Values from RFC1662
# fmt: off
_FCS_LOOKUP = (
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
)
# fmt: on


def _hostname_to_devicename(hostname: str) -> Optional[str]:
    """Extracts a lower-case device name from a host name in the way described
    in the module documentation. This does not yet attempt to find a suitable
    device.

    >>> _hostname_to_devicename("ttyacm0.dev.alt")
    'ttyacm0'
    >>> _hostname_to_devicename("example.com") is None
    True
    """
    if not hostname.endswith(".dev.alt"):
        return None

    if any(c not in _UNRESERVED for c in hostname):
        return None

    return hostname.removesuffix(".dev.alt")


def _checksum(data: bytes) -> bytes:
    """Calculates the Control message checksum (16-bit FCS from RFC1662),
    following its implementation in appendix C.2.

    >>> _checksum(b"coap is cool!")
    b'$&'
    """

    fcs = 0xFFFF
    for byte in data:
        fcs = (fcs >> 8) ^ _FCS_LOOKUP[(fcs ^ byte) & 0xFF]
    fcs ^= 0xFFFF
    return fcs.to_bytes(2, "little")


class SlipmuxAddress(interfaces.EndpointAddress):
    def __init__(self, hostname, interface):
        if _hostname_to_devicename(hostname) is None:
            raise ValueError(f"Not a recognized host name: {hostname!r}")
        # This is overly strict, but we can still relax, and this simplifies
        # eg. hostinfo, and won't need normalization.
        self._host = hostname
        self._interface = weakref.ref(interface)

    scheme = "coap"
    is_multicast = False
    is_multicast_locally = False

    interface = property(lambda self: self._interface())

    def __hash__(self):
        return hash(self._host)

    def __eq__(self, other):
        return self._host == other._host

    def __repr__(self):
        """
        >>> SlipmuxAddress("ttyusb0.dev.alt", MessageInterfaceSlipmux(..., ..., ..., ...))
        <SlipmuxAddress ttyusb0.dev.alt>
        """
        return "<%s %s>" % (
            type(self).__name__,
            self._host,
        )

    @property
    def hostinfo(self):
        return self._host

    @property
    def hostinfo_local(self):
        raise error.AnonymousHost

    @property
    def uri_base(self):
        return "coap://" + self.hostinfo

    @property
    def uri_base_local(self):
        raise error.AnonymousHost

    @property
    def blockwise_key(self):
        return self._host


class MessageInterfaceSlipmux(interfaces.MessageInterface):
    """Message Interface for Slipmux.

    As serial ports generally not be opened multiple times, this does not even
    try to manage running connections in the Endpoint objects, but spools
    endpoints until they break, at which point any attempt to send a message
    reconnects.

    This keeps any number of connections open with no attempts to limit them,
    as the number of serial connections a system has is generally way lower
    than any RAM limits.
    """

    def __init__(
        self, params: TransportParameters, ctx: interfaces.MessageManager, log, loop
    ):
        self.__ctx = ctx
        self.__log = log
        self.__pool: dict[SlipmuxAddress, SlipmuxProtocol] = {}
        self.__loop = loop
        self.__params = params
        self.__unixlisten_states: dict[SlipmuxAddress, _UnixListenState] = {}

    async def shutdown(self):
        for t in self.__unixlisten_states.values():
            t.shutdown()
        for proto in self.__pool.values():
            proto.transport.close()
        return

    async def _get(self, remote: SlipmuxAddress) -> SlipmuxProtocol:
        if remote in self.__pool:
            return self.__pool[remote]
        devicename = _hostname_to_devicename(remote._host)
        assert devicename is not None, "Checked at construction at recognition"

        starting_future = self.__loop.create_future()
        weakself = weakref.ref(self)
        connlog = self.__log.getChild(f"device-{devicename}")

        def protocol_factory():
            return SlipmuxProtocol(starting_future, weakself, remote, connlog)

        assert self.__params.slipmux is not None
        devparams = self.__params.slipmux.devices.get(devicename, SlipmuxDevice())
        if devparams.unix_connect is not None:
            (_, protocol) = await asyncio.get_running_loop().create_unix_connection(
                protocol_factory,
                # Type is ignored because mypy seems not to know that event
                # loops *do* accept paths.
                devparams.unix_connect,  # type: ignore
            )
        elif devparams.unix_listen is not None:
            # We only reach this when a request is sent there. Then
            # async-blocking on sending that request makes some sense: UNIX
            # sockets are used mostly in testing, and both sides need to be
            # ready to start talking. Suspending execution at the ._get() (and
            # thus recognizing the remote) will create some unexpected delays
            # when a process sends a request and then expects waiting for a
            # response to take long (rather than the initial recognition), but
            # that is probably fine.
            protocol = await self.__unixlisten_states[remote].get_waiting()
        else:
            full_devicename: Path | str | None = devparams.device
            if full_devicename is None:
                for filename in os.listdir("/dev/"):
                    if filename.lower() == devicename:
                        full_devicename = "/dev/" + filename
                        break
                else:
                    # sensible fallback for Windows, I guess
                    full_devicename = devicename
            (_, protocol) = await serial_asyncio.create_serial_connection(
                self.__loop,
                protocol_factory,
                full_devicename,
                baudrate=115200,
            )

        self.__pool[remote] = protocol
        startup_error = await starting_future
        if startup_error is not None:
            raise startup_error
        return protocol

    def _get_immediately(self, remote: SlipmuxAddress) -> SlipmuxProtocol:
        """Gets the relevant protcol, expecting that it is present (eg. when
        sending, because the remote was just recognized, which would have
        started the connection)"""
        return self.__pool[remote]

    def send(self, message):
        protocol = self._get_immediately(message.remote)
        # FIXME: Where do we best do this?
        if message.opt.uri_host == message.remote.hostinfo:
            message.opt.uri_host = None
        protocol.send_control(message.encode())

    async def recognize_remote(self, remote):
        if isinstance(remote, SlipmuxAddress) and remote.interface == self:
            # See determine_remote: from the current API, this is the only
            # asynchronous point before a send.
            await self._get(remote)
        return False

    async def determine_remote(self, message):
        # FIXME: Should we allow ports?
        if (
            message.remote.scheme == "coap"
            and _hostname_to_devicename(message.remote.hostinfo) is not None
        ):
            address = SlipmuxAddress(message.remote.hostinfo, self)
            # We have to connect now and await connection -- not just because
            # this gives us errors reasonably fast, but also because `.send` in
            # the message interface is synchronus.
            await self._get(address)
            return address

    @classmethod
    async def create_transport_endpoint(
        cls,
        params: TransportParameters,
        ctx: interfaces.MessageManager,
        log,
        loop,
    ):
        slef = cls(params, ctx, log, loop)
        if params.is_server:
            assert params.slipmux is not None
            for key, value in params.slipmux.devices.items():
                remote = SlipmuxAddress(f"{key}.dev.alt", slef)
                if value.unix_listen:
                    # _get would async-block, we need to spawn an actual task
                    # that'll keep working with incoming peers
                    unixlisten = slef.__unixlisten_states[remote] = _UnixListenState(
                        slef,
                        slef.__log.getChild(f"serverdevice-{key}"),
                        loop,
                        remote,
                        value,
                    )
                    await unixlisten.start()
                else:
                    await slef._get(remote)
        return slef

    # Provided for _UnixListenState

    def unixlisten_available(self, remote, protocol):
        self.__pool[remote] = protocol

    # provided for SlipmuxProtocol

    def received(self, remote, data):
        try:
            try:
                message = Message.decode(data, remote)
            except error.UnparsableMessage:
                self.__log.warning("Ignoring unparsable message from %s", remote)
                return

            self.__ctx.dispatch_message(message)

        except BaseException as exc:
            # Catching here because util.asyncio.recvmsg inherits
            # _SelectorDatagramTransport's bad handling of callback errors;
            # this is the last time we have a log at hand.
            self.__log.error(
                "Exception raised through dispatch_message: %s", exc, exc_info=exc
            )
            raise

    def terminated(self, remote, exception):
        if state := self.__unixlisten_states.get(remote):
            state.disconnected()
        self.__ctx.dispatch_error(exception, remote)


class SlipmuxProtocol(asyncio.Protocol):
    def __init__(self, starting_future, weakinstance, remote_handle, log):
        self.__starting = starting_future
        self.__instance = weakinstance
        self.__remote_handle = remote_handle
        self.__control_frame: Optional[list] = None
        self.__escape = False
        self.__log = log

    def send_control(self, data: bytes):
        data = bytes((HEADER_CONTROL,)) + data
        data += _checksum(data)
        data = data.replace(BYTE_ESC, BYTES_ESC_ESC_ESC).replace(
            BYTE_END, BYTES_ESC_ESC_END
        )
        # seems to be general practice to send leading ENDs generously
        data = BYTE_END + data + BYTE_END
        self.transport.write(data)

    def connection_made(self, transport):
        self.transport = transport
        self.__starting.set_result(None)

    def _end(self, is_regular: bool):
        """Restores the state after an END has been received.

        On a regular END condition, this checks the FCS and emits the frame, if
        any, and then resets; otherwise, it only resets."""
        if is_regular and isinstance(self.__control_frame, list):
            if len(self.__control_frame) < 2:
                self.__log.warn("Control frame too short")
            else:
                message = bytes(self.__control_frame[:-2])
                fcs = bytes(self.__control_frame[-2:])
                if fcs != _checksum(bytes((HEADER_CONTROL,)) + message):
                    self.__log.warn("FCS mismatch")
                else:
                    instance = self.__instance()
                    if instance is None:
                        self.__log.warn(
                            "Discarding incoming message: Instance shut down"
                        )
                    else:
                        instance.received(self.__remote_handle, message)
        self.__escape = False
        self.__control_frame = None

    def data_received(self, data):
        for byte in data:
            if self.__escape:
                match byte:
                    case slipmux.ESC_END:
                        byte = END
                    case slipmux.ESC_ESC:
                        byte = ESC
                    case slipmux.END:
                        self.__log.info("Frame has been aborted.")
                        self._end(False)
                        continue
                    case _:
                        self._end(False)
                        self.__log.warning(
                            "Framing error: Non-Escape value after Escape"
                        )
                        continue
                self.__escape = False
            else:
                if byte == ESC:
                    self.__escape = True
                    continue
                if byte == END:
                    self._end(True)
                    continue

            if self.__control_frame is None:
                if byte == HEADER_CONTROL:
                    self.__control_frame = []
                else:
                    self.__control_frame = False
                continue

            if isinstance(self.__control_frame, list):
                self.__control_frame.append(byte)

    def connection_lost(self, exc):
        if not self.__starting.done():
            self.set_result(exc)

        instance = self.__instance()
        if instance is None:
            self.__log.warn(
                "Discarding disconnect error (%r from %r): Instance shut down",
                exc,
                self.__remote_handler,
            )
        else:
            instance.terminated(self.__remote_handle, exc)

    # We do not implement pause_writing / resume_writing: the message interface
    # has no backpressure, so we'll just fill up the buffer, but given that
    # CoAP's flow control applies anyway (and it is way more conservative than
    # any actual UART's baud rate), there is little risk of excessive buffer
    # build-up.


class _UnixListenState:
    """Wrapper around a UNIX listening server. Serves one connection at a time."""

    def __init__(self, message_interface, log, loop, remote, transport_params):
        self.__message_interface = weakref.ref(message_interface)
        self.__log = log
        self.__loop = loop
        self.__remote = remote

        self.__unix_socket_filename = transport_params.unix_listen
        assert self.__unix_socket_filename is not None, (
            "_UnixListenState created on non-unix-listen transport config"
        )

        self.__current_connection = self.__loop.create_future()

    async def start(self):
        """Runs asynchronous initialization steps (creating the UNIX socket).

        Run this exactly once per instance, after init."""

        self.__server = await self.__loop.create_unix_server(
            self.protocol_factory,
            self.__unix_socket_filename,
        )

    def disconnected(self):
        self.__current_connection = self.__loop.create_future()

    def shutdown(self):
        self.__server.close()

    @property
    def message_interface(self) -> MessageInterfaceSlipmux:
        mi = self.__message_interface()
        if mi is None:
            self.__log.warn("Message interface vanished without a shutdown")
            raise asyncio.CancelledError
        return mi

    def protocol_factory(self):
        if self.__current_connection.done():

            class ShutDownImmediately:
                def connection_made(self, transport):
                    transport.write(
                        b"\xc0\nRefusing connection: a slipmux session is currently ongoing.\n\xc0"
                    )
                    transport.close()

                def connection_lost(self, exc):
                    pass

            return ShutDownImmediately()
        else:
            # We're not using it: As a listening UNIX socket we can trust that
            # when the future factory is called, an connection_made is run
            # immediately.
            starting_future = self.__loop.create_future()
            protocol = SlipmuxProtocol(
                starting_future, self.__message_interface, self.__remote, self.__log
            )
            self.__current_connection.set_result(protocol)
            self.message_interface.unixlisten_available(self.__remote, protocol)
            return protocol

    async def get_waiting(self) -> SlipmuxProtocol:
        """Returns the connected protocol, or waits until one is connected"""
        return await self.__current_connection
