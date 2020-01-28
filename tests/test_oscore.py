# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Tests for the aiocoap.oscore module based on the test vectors."""

import unittest

import aiocoap

oscore_modules = aiocoap.defaults.oscore_missing_modules()

if not oscore_modules:
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

    import aiocoap.oscore
    class NonsavingSecurityContext(aiocoap.oscore.SecurityContext):
        def post_seqnoincrease(self):
            # obviously, don't use this anywhere else, especially not with secret
            # keys
            pass

_skip_unless_oscore = unittest.skipIf(oscore_modules, "Modules missing for running OSCORE tests: %s" % (oscore_modules,))

@_skip_unless_oscore
class TestOSCOAPStatic(unittest.TestCase):
    def test_c1_1(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(secctx.sender_key, h('f0910ed7295e6ad4b54fc793154302ff'), "Sender key derivation disagrees with test vector")
        self.assertEqual(secctx.recipient_key, h('ffb14e093c94c9cac9471648b4f98710'), "Recipient key derivation disagrees with test vector")
        self.assertEqual(secctx.common_iv, h('4622d4dd6d944168eefb54987c'), "Common IV key derivation disagrees with test vector")

        sender_nonce_0 = secctx._construct_nonce(b"\0", secctx.sender_id)
        self.assertEqual(sender_nonce_0, h('4622d4dd6d944168eefb54987c'), "Sender nonce disagrees with test vector")
        recipient_nonce_0 = secctx._construct_nonce(b"\0", secctx.recipient_id)
        self.assertEqual(recipient_nonce_0, h('4722d4dd6d944169eefb54987c'), "Recipient nonce disagrees with test vector")

    def test_c1_2(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x01"
        secctx.recipient_id = b""
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(secctx.sender_key, h('ffb14e093c94c9cac9471648b4f98710'), "Sender key derivation disagrees with test vector")
        self.assertEqual(secctx.recipient_key, h('f0910ed7295e6ad4b54fc793154302ff'), "Recipient key derivation disagrees with test vector")
        self.assertEqual(secctx.common_iv, h('4622d4dd6d944168eefb54987c'), "Common IV key derivation disagrees with test vector")

        sender_nonce_0 = secctx._construct_nonce(b"\0", secctx.sender_id)
        self.assertEqual(sender_nonce_0, h('4722d4dd6d944169eefb54987c'), "Sender nonce disagrees with test vector")
        recipient_nonce_0 = secctx._construct_nonce(b"\0", secctx.recipient_id)
        self.assertEqual(recipient_nonce_0, h('4622d4dd6d944168eefb54987c'), "Recipient nonce disagrees with test vector")

    def test_c2_1(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x00"
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C2_SALT, C2_KEY)

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
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = C3_ID_CTX
        secctx.derive_keys(C3_SALT, C3_KEY)

        # info not compared; that would be tricky to extract and adds no value

        self.assertEqual(secctx.sender_key, h('af2a1300a5e95788b356336eeecd2b92'), "Sender key derivation disagrees with test vector")
        self.assertEqual(secctx.recipient_key, h('e39a0c7c77b43f03b4b39ab9a268699f'), "Recipient key derivation disagrees with test vector")
        self.assertEqual(secctx.common_iv, h('2ca58fb85ff1b81c0b7181b85e'), "Common IV key derivation disagrees with test vector")

        sender_nonce_0 = secctx._construct_nonce(b"\0", secctx.sender_id)
        self.assertEqual(sender_nonce_0, h('2ca58fb85ff1b81c0b7181b85e'), "Sender nonce disagrees with test vector")
        recipient_nonce_0 = secctx._construct_nonce(b"\0", secctx.recipient_id)
        self.assertEqual(recipient_nonce_0, h('2da58fb85ff1b81d0b7181b85e'), "Recipient nonce disagrees with test vector")


    def test_c4(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)
        secctx.sender_sequence_number = 20


        unprotected = aiocoap.Message.decode(h('44015d1f00003974396c6f63616c686f737483747631'))
        outer_message, _ = secctx.protect(unprotected)
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(encoded, h('44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e'), "Encoded message differs")

    def test_c5(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x00"
        secctx.recipient_id = b"\x01"
        secctx.id_context = None
        secctx.derive_keys(C2_SALT, C2_KEY)
        secctx.sender_sequence_number = 20


        unprotected = aiocoap.Message.decode(h('440171c30000b932396c6f63616c686f737483747631'))
        outer_message, _ = secctx.protect(unprotected)
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(encoded, h('440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0'), "Encoded message differs")

    def test_c6(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b""
        secctx.recipient_id = b"\x01"
        secctx.id_context = C3_ID_CTX
        secctx.derive_keys(C3_SALT, C3_KEY)
        secctx.sender_sequence_number = 20


        unprotected = aiocoap.Message.decode(h('44012f8eef9bbf7a396c6f63616c686f737483747631'))
        outer_message, _ = secctx.protect(unprotected, kid_context=True)
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        # FIXME: This is composed from the expected ciphertext, not the protected coap request, see https://github.com/core-wg/oscoap/issues/241
        self.assertEqual(encoded, h('44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff72cd7273fd331ac45cffbe55c3'), "Encoded message differs")


    def test_c7(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x01"
        secctx.recipient_id = b""
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)


        unprotected = aiocoap.Message.decode(h('64455d1f00003974ff48656c6c6f20576f726c6421'))
        request_sender_id = secctx.recipient_id
        request_piv_short = b"\x14"
        request_nonce = secctx._construct_nonce(request_piv_short, request_sender_id)
        outer_message, _ = secctx.protect(unprotected, aiocoap.oscore.RequestIdentifiers(request_sender_id, request_piv_short, request_nonce, True))
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(encoded, h('64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106'), "Encoded message differs")

    def test_c8(self):
        secctx = NonsavingSecurityContext()
        secctx.algorithm = default_algorithm
        secctx.hashfun = default_hashfun
        secctx.sender_id = b"\x01"
        secctx.recipient_id = b""
        secctx.id_context = None
        secctx.derive_keys(C1_SALT, C1_KEY)
        secctx.sender_sequence_number = 0


        unprotected = aiocoap.Message.decode(h('64455d1f00003974ff48656c6c6f20576f726c6421'))
        request_sender_id = secctx.recipient_id
        request_piv_short = b"\x14"
        request_nonce = secctx._construct_nonce(request_piv_short, request_sender_id)
        outer_message, _ = secctx.protect(unprotected, aiocoap.oscore.RequestIdentifiers(request_sender_id, request_piv_short, request_nonce, False))
        outer_message.mid = unprotected.mid
        outer_message.token = unprotected.token
        outer_message.mtype = unprotected.mtype

        # again skipping some intermediary values that are all checked in the final result as well

        encoded = outer_message.encode()
        self.assertEqual(encoded, h('64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e'), "Encoded message differs")

