#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This is a usage example of aiocoap that demonstrates how to implement a
simple server. See the "Usage Examples" section in the aiocoap documentation
for some more information."""

import asyncio
import logging
from os import environ

import aiocoap
import aiocoap.resource as resource
from aiocoap import Message
from aiocoap.numbers.codes import Code
# logging setup
from server import TimeResource, BlockResource, SeparateLargeResource

logging.basicConfig(level=logging.INFO)
LOGGER_NAME = "coap-client-server"
logging.getLogger(LOGGER_NAME).setLevel(logging.DEBUG)


async def run_bi_directional_coap_server(root):
    """ Bidirectional in the sense that the TCP server will send requests to it's client (connections) and will
    act as client as well.

    This approach is interesting when the (UDP/TCP) client is in a private network.

    In this example an tcp connection is preferred because this library stores all incoming connection in a pool.
    The server sends a client request every 10 seconds to each opened (incoming) connection.
    """
    environ['AIOCOAP_SERVER_TRANSPORT'] = "tcpserver"  # Dirty hack to force tcp communication

    protocol = await aiocoap.Context.create_server_context(root, bind=("", aiocoap.COAP_PORT), loggername=LOGGER_NAME)

    # Assumed that there is only 1 transport endpoint, namely the 'tcpserver'
    tcp_server_interface = protocol.request_interfaces[0].token_interface

    while True:
        await asyncio.sleep(10)

        for conn in tcp_server_interface._pool:  # Hack to obtain the list of existing connections.
            request = Message(code=Code.GET)
            request.remote = conn

            request.opt.uri_path = ["time"]

            try:
                logging.getLogger(LOGGER_NAME).info("Sending request to connection %s", conn.hostinfo)
                response = await protocol.request(request, handle_blockwise=False).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r' % (response.code, response.payload))

        logging.info("Sleeping for 10 seconds")


def main():
    # Resource tree creation
    root = resource.Site()

    root.add_resource(('.well-known', 'core'), resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(('time',), TimeResource())
    root.add_resource(('other', 'block'), BlockResource())
    root.add_resource(('other', 'separate'), SeparateLargeResource())

    asyncio.Task(run_bi_directional_coap_server(root))

    asyncio.get_event_loop().run_forever()


if __name__ == "__main__":
    main()
