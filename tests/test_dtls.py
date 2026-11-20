# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import errno
import unittest
from unittest import mock

import aiocoap

from . import common
from .test_server import TestServer, WithClient, WithTestServer

PSK = "the PSK key"
identity = "test-client"


class WithDTLSClient(WithClient):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        # FIXME shouldn't that only need the servernamealias?
        self.client.client_credentials.load_from_dict(
            {
                "coaps://%s/*" % self.servernamealias: {
                    "dtls": {
                        "psk": {"ascii": PSK},
                        "client-identity": {"ascii": identity},
                    }
                }
            }
        )
        self.client.client_credentials.load_from_dict(
            {
                "coaps://%s/*" % self.servernetloc: {
                    "dtls": {
                        "psk": {"ascii": PSK},
                        "client-identity": {"ascii": identity},
                    }
                }
            }
        )


class WithDTLSServer(WithTestServer):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.server.server_credentials.load_from_dict(
            {
                ":client": {
                    "dtls": {
                        "psk": {"ascii": PSK},
                        "client-identity": {"ascii": identity},
                    }
                }
            }
        )


dtls_modules = aiocoap.defaults.dtls_missing_modules()


@unittest.skipIf(
    dtls_modules or common.dtls_disabled,
    "DTLS missing modules (%s) or disabled in this environment" % (dtls_modules,),
)
class TestServerDTLS(TestServer, WithDTLSClient, WithDTLSServer):
    # as with TestServerTCP

    def build_request(self):
        request = super().build_request()
        # odd default port
        request.requested_scheme = "coaps"
        return request


class TestDTLSClientShutdown(unittest.TestCase):
    """DTLSClientConnection.shutdown tests that need no DTLS module."""

    def _connection_whose_close_alert_fails(self):
        """A connection whose close alert fails and re-enters shutdown()."""
        from aiocoap.transports.tinydtls import DTLSClientConnection

        connection = DTLSClientConnection.__new__(DTLSClientConnection)
        connection._remove_from_pool = mock.Mock()
        connection._startup = mock.Mock()
        connection._retransmission_task = mock.Mock()
        connection._transport = mock.Mock()
        connection._dtls_socket = mock.Mock()
        connection.coaptransport = mock.Mock()
        connection._connection = mock.sentinel.peer

        def reset_peer(_peer):
            connection._inject_error(
                OSError(errno.ENETUNREACH, "Network is unreachable")
            )

        connection._dtls_socket.resetPeer.side_effect = reset_peer
        return connection

    def test_failing_close_alert_resets_peer_once(self):
        """A failing close alert does not reset the peer twice."""
        connection = self._connection_whose_close_alert_fails()

        connection.shutdown()

        connection._dtls_socket.resetPeer.assert_called_once_with(mock.sentinel.peer)
        self.assertIsNone(connection._connection)
        connection._transport.close.assert_called()
        connection.coaptransport.ctx.dispatch_error.assert_called_once()

    def test_error_then_failing_close_alert_resets_peer_once(self):
        """Same when shutdown starts from an error; both errors are dispatched."""
        connection = self._connection_whose_close_alert_fails()

        connection._inject_error(OSError(errno.ENETUNREACH, "Network is unreachable"))

        connection._dtls_socket.resetPeer.assert_called_once_with(mock.sentinel.peer)
        self.assertIsNone(connection._connection)
        self.assertEqual(connection.coaptransport.ctx.dispatch_error.call_count, 2)


del TestServer

if __name__ == "__main__":
    # due to the imports, you'll need to run this as `python3 -m tests.test_server`
    common.run_fixture_as_standalone_server(WithDTLSServer)
