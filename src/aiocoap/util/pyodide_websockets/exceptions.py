# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT


class WebSocketException(Exception):
    pass


class ConnectionClosed(WebSocketException):
    pass
