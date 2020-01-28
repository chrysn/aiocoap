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
import aiocoap.defaults

class TestCredentialsLoad(unittest.TestCase):
    def test_load_empty(self):
        raw = {}
        m = CredentialsMap()
        m.load_from_dict(raw)
        self.assertEqual(type(m), CredentialsMap)
        self.assertEqual(len(m), 0)

    def test_dtls(self):
        raw = {
            'coaps://some-dtls-host/*': {'dtls': {'psk': {'hex': '73-65-63-72-65-74-50-53-4b'}, 'client-identity': b'Client_identity'}}
            }

        m = CredentialsMap()
        m.load_from_dict(raw)
        # note we can use the slash-free version here and still get the result
        # for //some-host/* due to the URI normalization rules
        message = Message(code=GET, uri='coaps://some-dtls-host')
        secmatch = m.credentials_from_request(message)
        self.assertEqual(type(secmatch), DTLS)
        self.assertEqual(secmatch.psk, b'secretPSK')
        self.assertEqual(secmatch.client_identity, b'Client_identity')

    @unittest.skipIf(aiocoap.defaults.oscore_missing_modules(), "Modules missing for loading OSCORE contexts: %s"%(aiocoap.defaults.oscore_missing_modules(),))
    def test_oscore_filebased(self):
        from aiocoap.oscore import FilesystemSecurityContext

        raw = {
            'coap://some-oscore-host/*': {'oscore': {'contextfile': __file__.replace('test_credentials.py', 'test_credentials_oscore_context/')}},
            'coaps://some-dtls-host/*': {'dtls': {'psk': {'hex': '73-65-63-72-65-74-50-53-4b'}, 'client-identity': b'Client_identity'}}
            }

        m = CredentialsMap()
        m.load_from_dict(raw)
        message = Message(code=GET, uri='coap://some-oscore-host/.well-known/core')
        secmatch = m.credentials_from_request(message)
        self.assertEqual(type(secmatch), FilesystemSecurityContext)
