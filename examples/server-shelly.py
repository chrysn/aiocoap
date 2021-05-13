#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This is a usage example of aiocoap that demonstrates how to implement
a simple server for non-standard publishing methods (i.e. neither PUT
nor POST).

This example is created for Shelly devices, which implement CoIoT protocol
based on COAP

    https://shelly-api-docs.shelly.cloud/docs/coiot/v1/CoIoT%20for%20Shelly%20devices%20(rev%201.0)%20.pdf

"""

import asyncio
import logging
import json
from datetime import datetime

import aiocoap.resource as resource
import aiocoap

# device ids for some of sensors in Shelly devices
DEVICES = {
    3108: 'door/window',
    3106: 'light',
    3101: 'temperature',
    3102: 'light',
}


class ShellyResource(resource.Resource):
    """Resource to receive data via non-standard method.
    """
    async def render(self, request):
        """Non-standard method implementation for Shelly devices. 
        """
        # find device id
        option = request.opt.get_option(3332)
        device_id = option[0].value.decode()

        data = json.loads(request.payload)
        sensor_data = data['G']

        print('{}: {}'.format(datetime.now(), device_id))
        for _, sensor_id, value in data['G']:
            # if device id cannot be mapped, then simply use its id
            name = DEVICES.get(sensor_id, sensor_id)
            print('  {}: {}'.format(name, value))
        print()

        return aiocoap.Message(code=aiocoap.CHANGED)


logging.basicConfig(level=logging.DEBUG)
logging.getLogger('coap-server').setLevel(logging.DEBUG)

root = resource.Site()
root.add_resource(['.well-known', 'core'],
        resource.WKCResource(root.get_resources_as_linkheader))

# each device publishes to cit/s URI
root.add_resource(['cit', 's'], ShellyResource())

asyncio.Task(aiocoap.Context.create_server_context(root))
asyncio.get_event_loop().run_forever()
