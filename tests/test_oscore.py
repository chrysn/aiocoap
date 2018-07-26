# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Tests for the aiocoap.oscore module based on the test vectors."""

import unittest

import aiocoap.oscore

# shortcut definition, as this will be used all over the place with copy-pasted
# values from the specification
h = bytes.fromhex

C1_KEY = h('0102030405060708090a0b0c0d0e0f10')
C1_SALT = h('9e7ca92223786340')

C2_KEY = h('0102030405060708090a0b0c0d0e0f10')
C2_SALT = None

C3_KEY = h('0102030405060708090a0b0c0d0e0f10')
C3_SALT = h('9e7ca92223786340')
C3_ID_CTX = h('37cbf3210017a2d3')

default_algorithm = aiocoap.oscore.AES_CCM_16_64_128
default_hashfun = aiocoap.oscore.hashfunctions['sha256']

class TestOSCOAPStatic(unittest.TestCase):
    def test_c1_1(self):
        secctx = aiocoap.oscore.SecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.derive_keys(C1_SALT, C1_KEY, None)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(secctx.sender_key, h('f0910ed7295e6ad4b54fc793154302ff'), "Sender key derivation disagrees with test vector")
        self.assertEqual(secctx.recipient_key, h('ffb14e093c94c9cac9471648b4f98710'), "Recipient key derivation disagrees with test vector")
        self.assertEqual(secctx.common_iv, h('4622d4dd6d944168eefb54987c'), "Common IV key derivation disagrees with test vector")

        sender_nonce_0 = secctx._construct_nonce(b"\0", secctx.sender_id)
        self.assertEqual(sender_nonce_0, h('4622d4dd6d944168eefb54987c'), "Sender nonce disagrees with test vector")
        recipient_nonce_0 = secctx._construct_nonce(b"\0", secctx.recipient_id)
        self.assertEqual(recipient_nonce_0, h('4722d4dd6d944169eefb54987c'), "Recipient nonce disagrees with test vector")

    def test_c1_2(self):
        secctx = aiocoap.oscore.SecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x01"
        secctx.recipient_id = b""
        secctx.derive_keys(C1_SALT, C1_KEY, None)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(secctx.sender_key, h('ffb14e093c94c9cac9471648b4f98710'), "Sender key derivation disagrees with test vector")
        self.assertEqual(secctx.recipient_key, h('f0910ed7295e6ad4b54fc793154302ff'), "Recipient key derivation disagrees with test vector")
        self.assertEqual(secctx.common_iv, h('4622d4dd6d944168eefb54987c'), "Common IV key derivation disagrees with test vector")

        sender_nonce_0 = secctx._construct_nonce(b"\0", secctx.sender_id)
        self.assertEqual(sender_nonce_0, h('4722d4dd6d944169eefb54987c'), "Sender nonce disagrees with test vector")
        recipient_nonce_0 = secctx._construct_nonce(b"\0", secctx.recipient_id)
        self.assertEqual(recipient_nonce_0, h('4622d4dd6d944168eefb54987c'), "Recipient nonce disagrees with test vector")

    def test_c2_1(self):
        secctx = aiocoap.oscore.SecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x00"
        secctx.recipient_id = b"\x01"
        secctx.derive_keys(C2_SALT, C2_KEY, None)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(secctx.sender_key, h('321b26943253c7ffb6003b0b64d74041'), "Sender key derivation disagrees with test vector")
        self.assertEqual(secctx.recipient_key, h('e57b5635815177cd679ab4bcec9d7dda'), "Recipient key derivation disagrees with test vector")
        self.assertEqual(secctx.common_iv, h('be35ae297d2dace910c52e99f9'), "Common IV key derivation disagrees with test vector")

        sender_nonce_0 = secctx._construct_nonce(b"\0", secctx.sender_id)
        self.assertEqual(sender_nonce_0, h('bf35ae297d2dace910c52e99f9'), "Sender nonce disagrees with test vector")
        recipient_nonce_0 = secctx._construct_nonce(b"\0", secctx.recipient_id)
        self.assertEqual(recipient_nonce_0, h('bf35ae297d2dace810c52e99f9'), "Recipient nonce disagrees with test vector")

    # skipping the server side for c.2.2 as it is very redundant

    def test_c3_1(self):
        secctx = aiocoap.oscore.SecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.derive_keys(C3_SALT, C3_KEY, C3_ID_CTX)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(secctx.sender_key, h('af2a1300a5e95788b356336eeecd2b92'), "Sender key derivation disagrees with test vector")
        self.assertEqual(secctx.recipient_key, h('e39a0c7c77b43f03b4b39ab9a268699f'), "Recipient key derivation disagrees with test vector")
        self.assertEqual(secctx.common_iv, h('2ca58fb85ff1b81c0b7181b85e'), "Common IV key derivation disagrees with test vector")

        sender_nonce_0 = secctx._construct_nonce(b"\0", secctx.sender_id)
        self.assertEqual(sender_nonce_0, h('2ca58fb85ff1b81c0b7181b85e'), "Sender nonce disagrees with test vector")
        recipient_nonce_0 = secctx._construct_nonce(b"\0", secctx.recipient_id)
        self.assertEqual(recipient_nonce_0, h('2da58fb85ff1b81d0b7181b85e'), "Recipient nonce disagrees with test vector")

    # FIXME: Add C.4 ff.
