# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Tests for the aiocoap.credentials module. This does not test the
functionality of the ciphers, just the syntax of loading them."""

import unittest

from aiocoap import Message, GET
from aiocoap.credentials import CredentialsMap, DTLS

class TestCredentialsLoad(unittest.TestCase):
    def test_load_empty(self):
        raw = {}
        m = CredentialsMap.from_dict(raw)
        self.assertEqual(type(m), CredentialsMap)
        self.assertEqual(len(m), 0)

    def test_dtls(self):
        raw = {
                '*': {'oscore': {'contextfile':'/dev/null'}},
                'coaps://some-host/*': {'dtls': {'psk': b'secretPSK', 'client-identity': b'Client_identity'}}
                }
        m = CredentialsMap.from_dict(raw)
        # note we can use the slash-free version here and still get the result
        # for //some-host/* due to the URI normalization rules
        message = Message(code=GET, uri='coaps://some-host')
        secmatch = m.credentials_from_request(message)
        self.assertEqual(type(secmatch), DTLS)
        self.assertEqual(secmatch.psk, b'secretPSK')
        self.assertEqual(secmatch.client_identity, b'Client_identity')
