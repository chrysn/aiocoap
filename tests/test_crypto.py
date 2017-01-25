# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Tests for the util.crypto module"""

import unittest

import aiocoap.util.crypto

class TestUtilCrypto(unittest.TestCase):
    def test_reproduced_output(self):
        """Reproducibility of encryption results, decryption and detecting
        tampered AAD

        These values were not verified by themselves with another
        implementation, but the function that produced them produced valid key
        material in OSCOAP."""

        key = b"0123456789----------0123456789--"
        iv = b"1234567"
        message = b"Hello Bob, this is Alice."
        aad = b"The envelope said that this is from Alice to Bob."

        ciphertext, tag = aiocoap.util.crypto.encrypt_ccm(message, aad, key, iv, 14)
        self.assertEqual(ciphertext, b'g^\xc9X\xednx\xd5\xc6\xab\x8c\x85\xaa\xed\\f\xee\xebk\xbc]SCZ\x85')
        self.assertEqual(tag, b'P\xce0{K\xaf*\xf9\xb1\xb4\xbc\x1c\x84_')

        decrypted = aiocoap.util.crypto.decrypt_ccm(ciphertext, aad, tag, key, iv)
        self.assertEqual(decrypted, message)

        self.assertRaises(aiocoap.util.crypto.InvalidAEAD, aiocoap.util.crypto.decrypt_ccm, ciphertext, b"The envelope said this is from Michelle to Bob.", tag, key, iv)
