# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import aiocoap

import unittest

class TestMessage(unittest.TestCase):
    normal_uris = [
            'coap://hostname:1234/path',
            'coap://hostname:1234/path?query=string&argument=x',
            'coap+tcp://hostname/path',
            'coaps://hostname:1234/path',
            ]

    def test_normal(self):
        for n in self.normal_uris:
            msg = aiocoap.Message(code=aiocoap.GET, uri=n)
            self.assertEqual(msg.get_request_uri(), n, "Encoding normal URI to a message did not round-trip the URI")

    # These do not map URIs to their fully normalzied form, just to another
    # (possibly normalized) form that is equivalent under normalization rules.
    # Thus, it might be perfectly OK for an implemention change to require
    # changing the test case -- as long as the new result sill has the same
    # normal URI.
    denormal_uris = {
            'coap://hostname:1234': 'coap://hostname:1234/',
            'CoAp://HoStNaMe/': 'coap://hostname/',
            'coap://host/%7Esensors': 'coap://host/~sensors',
            'coap://hostname:5683/path': 'coap://hostname:5683/path', # could strip the port
            'coap://host/blåbærsyltetøy': 'coap://host/bl%C3%A5b%C3%A6rsyltet%C3%B8y',
            }

    def test_denormal(self):
        for src, dest in self.denormal_uris.items():
            msg = aiocoap.Message(code=aiocoap.GET, uri=src)
            self.assertEqual(msg.get_request_uri(), dest,
                            "Encoding normal URI to a message did not"
                            " round-trip the URI (original: %r)" % src)
