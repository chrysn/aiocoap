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
    class NonsavingSecurityContext(aiocoap.oscore.CanProtect, aiocoap.oscore.CanUnprotect, aiocoap.oscore.SecurityContextUtils):
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

@_skip_unless_oscore
class TestOSCOAAsymmetric(unittest.TestCase):
    """Test asymmetric algorithms

    As the Group OSCORE document currently has no test vectors, this is using
    values from the IETF109 hackathon.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # From https://github.com/ace-wg/Hackathon-109/blob/master/GroupKeys.md,
        # "Rikard Test 1"

        self.r1_1_d = bytes.fromhex('FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E6')
        self.r1_1_y = bytes.fromhex('64CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB0684')
        self.r1_1_x = bytes.fromhex('1ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC96')

        self.r1_2_d = bytes.fromhex('DA2593A6E0BCC81A5941069CB76303487816A2F4E6C0F21737B56A7C90381597')
        self.r1_2_y = bytes.fromhex('1897A28666FE1CC4FACEF79CC7BDECDC271F2A619A00844FCD553A12DD679A4F')
        self.r1_2_x = bytes.fromhex('0EB313B4D314A1001244776D321F2DD88A5A31DF06A6EEAE0A79832D39408BC1')

        self.r1_3_d = bytes.fromhex('BF31D3F9670A7D1342259E700F48DD9983A5F9DF80D58994C667B6EBFD23270E')
        self.r1_3_y = bytes.fromhex('5694315AD17A4DA5E3F69CA02F83E9C3D594712137ED8AFB748A70491598F9CD')
        self.r1_3_x = bytes.fromhex('FAD4312A45F45A3212810905B223800F6CED4BC8D5BACBC8D33BB60C45FC98DD')

        # "Rikard Test 2"
        self.r2_csalg = -8
        self.r2_csalg_params = [[1], [1, 6]]

        self.r2_1_private = bytes.fromhex('397CEB5A8D21D74A9258C20C33FC45AB152B02CF479B2E3081285F77454CF347')
        self.r2_1_public = bytes.fromhex('CE616F28426EF24EDB51DBCEF7A23305F886F657959D4DF889DDFC0255042159')

        self.r2_2_private = bytes.fromhex('70559B9EECDC578D5FC2CA37F9969630029F1592AFF3306392AB15546C6A184A')
        self.r2_2_public = bytes.fromhex('2668BA6CA302F14E952228DA1250A890C143FDBA4DAED27246188B9E42C94B6D')

        self.r2_3_private = bytes.fromhex('E550CD532B881D52AD75CE7B91171063E568F2531FBDFB32EE01D1910BCF810F')
        self.r2_3_public = bytes.fromhex('5394E43633CDAC96F05120EA9F21307C9355A1B66B60A834B53E9BF60B1FB7DF')

        # from https://github.com/ace-wg/Hackathon-109/blob/master/GroupDerivation.md

        self.r1_shared_12 = bytes.fromhex('56ede6c59e919031cfc8afa3e74a7b7615c2e7a08494cf3638c78757293adc80')
        self.r1_shared_13 = bytes.fromhex('f568ec5f7df45db137fc79a27595eba737b62e8ee385c7309e316dd409de6953')

        # Not actually used; these are already verified in tests_util_cryptography's vectors
        self.r2_shared_12 = bytes.fromhex('4546babdb9482396c167af11d21953bfa49eb9f630c45de93ee4d3b9ef059576')
        self.r2_shared_13 = bytes.fromhex('bb11648af3dfebb35e612914a7a21fc751b001aceb0267c5536528e2b9261450')

    def alg(self):
        all_par = [self.r2_csalg, self.r2_csalg_params]
        # FIXME we probably need an algorithm finder from value_all_par
        alg = aiocoap.oscore.Ed25519()
        self.assertEqual(alg.value_all_par, all_par)
        return alg

    def test_publickey_derivation(self):
        alg = self.alg()
        self.assertEqual(self.r2_1_public, alg.public_from_private(self.r2_1_private))
        self.assertEqual(self.r2_2_public, alg.public_from_private(self.r2_2_private))
        self.assertEqual(self.r2_3_public, alg.public_from_private(self.r2_3_private))

    def _test_keypair(self, alg, private, public):
        body = b""
        aad = b""
        signature = alg.sign(body, aad, private)
        alg.verify(signature, body, aad, public)

        self.assertRaises(aiocoap.oscore.ProtectionInvalid, lambda: alg.verify(signature, body + b"x", aad, public))

    def test_publickey_signatures(self):
        alg = self.alg()

        self._test_keypair(alg, self.r2_1_private, self.r2_1_public)
        self._test_keypair(alg, self.r2_2_private, self.r2_2_public)
        self._test_keypair(alg, self.r2_3_private, self.r2_3_public)

    def test_generation(self):
        alg = self.alg()

        for alg in aiocoap.oscore.algorithms_countersign.values():
            random_key = alg.generate()
            public_key = alg.public_from_private(random_key)

            self._test_keypair(alg, random_key, public_key)

            second_random = alg.generate()
            second_public = alg.public_from_private(second_random)
            self.assertEqual(alg.staticstatic(random_key, second_public), alg.staticstatic(second_random, public_key))

    def test_ecdsa_vectors(self):
        alg = aiocoap.oscore.ECDSA_SHA256_P256()

        r1_1 = alg.from_private_parts(self.r1_1_x, self.r1_1_y, self.r1_1_d)
        r1_2 = alg.from_private_parts(self.r1_2_x, self.r1_2_y, self.r1_2_d)
        r1_3 = alg.from_private_parts(self.r1_3_x, self.r1_3_y, self.r1_3_d)

        self.assertEqual(alg.staticstatic(r1_1, alg.public_from_private(r1_2)), self.r1_shared_12)
        self.assertEqual(alg.staticstatic(r1_3, alg.public_from_private(r1_1)), self.r1_shared_13)

@_skip_unless_oscore
class TestOSCORECompression(unittest.TestCase):
    def compare_uncompress(self, ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext):
        message = aiocoap.Message(payload=ref_payload, object_security=ref_option)
        protected_serialized, protected, unprotected, ciphertext = aiocoap.oscore.CanUnprotect._extract_encrypted0(message)

        self.assertEqual(protected, ref_protected, "Protected dictionary mismatch")
        self.assertEqual(unprotected, ref_unprotected, "Unprotected dictionary mismatch")
        self.assertEqual(ciphertext, ref_ciphertext, "Ciphertext mismatch")

    def compare_compress(self, ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext):
        option, payload = aiocoap.oscore.CanProtect._compress(ref_protected, ref_unprotected, ref_ciphertext)

        self.assertEqual(option, ref_option, "Compressed option mismatch")
        self.assertEqual(payload, ref_payload, "Compressed payload mismatch")

    def compare_all(self, ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext):
        self.compare_uncompress(ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext)
        self.compare_compress(ref_option, ref_payload, ref_protected, ref_unprotected, ref_ciphertext)

    def test_empty(self):
        self.compare_all(b"", b"1234", {}, {}, b"1234")

    def test_short(self):
        self.compare_all(b"\x01\x00", b"1234", {}, {aiocoap.oscore.COSE_PIV: b"\x00"}, b"1234")

    def test_long(self):
        self.compare_all(b"\x05ABCDE", b"1234", {}, {aiocoap.oscore.COSE_PIV: b"ABCDE"}, b"1234")

    def test_kid(self):
        self.compare_all(b"\x0bABC--------", b"1234", {}, {aiocoap.oscore.COSE_PIV: b"ABC", aiocoap.oscore.COSE_KID: b"--------"}, b"1234")

    def test_idcontext(self):
        self.compare_all(b"\x1bABC\x03abc--------", b"1234", {}, {aiocoap.oscore.COSE_PIV: b"ABC", aiocoap.oscore.COSE_KID: b"--------", aiocoap.oscore.COSE_KID_CONTEXT: b"abc"}, b"1234")

    def test_idcontext_nopiv(self):
        self.compare_all(b"\x18\x03abc--------", b"1234", {}, {aiocoap.oscore.COSE_KID: b"--------", aiocoap.oscore.COSE_KID_CONTEXT: b"abc"}, b"1234")

    def test_counterisgnature(self):
        # This is only as correct as it gets with the interactions between
        # determining the countersignature (or its length) and uncompression:
        # The flag is registered, but its value is empty (deferring to a later
        # step that'd actually know the algorithm) and relies on the later
        # process to move data over from the plaintext
        self.compare_all(b"\x2bABC--", b"1234sigsigsig", {}, {aiocoap.oscore.COSE_PIV: b"ABC", aiocoap.oscore.COSE_KID: b"--", aiocoap.oscore.COSE_COUNTERSINGATURE0: b""}, b"1234sigsigsig")

    def test_reserved(self):
        self.assertRaises(aiocoap.oscore.DecodeError, lambda: self.compare_uncompress(b"\x4bABC--", b"1234", None, None, None))
        self.assertRaises(aiocoap.oscore.DecodeError, lambda: self.compare_uncompress(b"\x8bABC--", b"1234", None, None, None))

    def test_unknown(self):
        self.assertRaises(RuntimeError, lambda: self.compare_compress(None, None, {"x": "y"}, {}, b""))
        self.assertRaises(RuntimeError, lambda: self.compare_compress(None, None, {}, {"x": "y"}, b""))
