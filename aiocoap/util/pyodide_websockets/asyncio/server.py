# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from .connection import Connection


class ServerConnection(Connection):
    def __init__(self, *args, **kwargs):
        raise RuntimeError("Web sockets in web browsers can not be used as servers")


class Server:
    def __init__(self, *args, **kwargs):
        raise RuntimeError("Web sockets in web browsers can not be used as servers")


async def serve(*args, **kwargs) -> Server:
    return Server()
