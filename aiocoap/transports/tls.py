# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""
CoAP-over-TLS transport (early work in progress)

Right now this is running on self-signed, hard-coded certificates with default
SSL module options.

To use this, generate keys as with::

    $ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 5 -nodes

and state your hostname (eg. localhost) when asked for the Common Name.
"""

from .tcp import TCPClient, TCPServer

from aiocoap import COAPS_PORT

class _TLSMixIn:
    _scheme = 'coaps+tcp'
    _default_port = COAPS_PORT

class TLSServer(_TLSMixIn, TCPServer):
    @classmethod
    async def create_server(cls, bind, tman, log, loop, server_context):
        return await super().create_server(bind, tman, log, loop, _server_context=server_context)

class TLSClient(_TLSMixIn, TCPClient):
    def _ssl_context_factory(self, hostinfo):
        c = self.credentials.ssl_client_context(self._scheme, hostinfo)
        if c is None:
            import ssl
            c = ssl.create_default_context()
        c.set_alpn_protocols(["coap"])
        return c
