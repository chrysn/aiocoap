# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import aiocoap

import unittest


class TestMessage(unittest.TestCase):
    normal_uris = [
        "coap://hostname:1234/path",
        "coap://hostname:1234/path?query=string&argument=x",
        "coap+tcp://hostname/path",
        "coaps://hostname:1234/path",
    ]

    def test_normal(self):
        for n in self.normal_uris:
            msg = aiocoap.Message(code=aiocoap.GET, uri=n)
            self.assertEqual(
                msg.get_request_uri(),
                n,
                "Encoding normal URI to a message did not round-trip the URI",
            )

    # These do not map URIs to their fully normalzied form, just to another
    # (possibly normalized) form that is equivalent under normalization rules.
    # Thus, it might be perfectly OK for an implementation change to require
    # changing the test case -- as long as the new result sill has the same
    # normal URI.
    denormal_uris = {
        "coap://hostname:1234": "coap://hostname:1234/",
        "CoAp://HoStNaMe/": "coap://hostname/",
        "coap://host/%7Esensors": "coap://host/~sensors",
        "coap://hostname:5683/path": "coap://hostname:5683/path",  # could strip the port
        "coap://host/blåbærsyltetøy": "coap://host/bl%C3%A5b%C3%A6rsyltet%C3%B8y",
    }

    def test_denormal(self):
        for src, dest in self.denormal_uris.items():
            msg = aiocoap.Message(code=aiocoap.GET, uri=src)
            self.assertEqual(
                msg.get_request_uri(),
                dest,
                "Encoding normal URI to a message did not"
                " round-trip the URI (original: %r)" % src,
            )

    erring_uris = {
        "/hello": aiocoap.error.IncompleteUrlError,
        "coap://[": aiocoap.error.MalformedUrlError,
        "coap://example.com/%ff": aiocoap.error.MalformedUrlError,
        "coap://example.com:fivesixeightthree/": aiocoap.error.MalformedUrlError,
        # not broken per URI specs, but CoAP uses the hostname component,
        # and urllib uses information about which schemes use it.
        "coap:like:urn": aiocoap.error.MalformedUrlError,
    }

    def test_errors(self):
        for uri, expected in self.erring_uris.items():
            with self.assertRaises(expected):
                aiocoap.Message(code=aiocoap.GET, uri=uri)

    uris_using_proxy = {
        "http://example.com/test",
        "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66",
    }

    def test_turned_into_proxy(self):
        for uri in self.uris_using_proxy:
            msg = aiocoap.Message(code=aiocoap.GET, uri=uri)
            self.assertEqual(msg.opt.proxy_uri, uri)
