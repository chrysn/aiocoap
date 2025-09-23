# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import copy

import aiocoap
import aiocoap.optiontypes

import unittest


class TestMessage(unittest.TestCase):
    def test_encode(self):
        msg1 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)
        binary1 = bytes((64, 0, 0, 0))
        self.assertEqual(
            msg1.encode(), binary1, "wrong encode operation for empty CON message"
        )

        msg2 = aiocoap.Message(
            _mtype=aiocoap.ACK,
            _mid=0xBC90,
            code=aiocoap.CONTENT,
            payload=b"temp = 22.5 C",
            _token=b"q",
        )
        msg2.opt.etag = b"abcd"
        binary2 = (
            bytes((97, 69, 188, 144, 113, 68))
            + b"abcd"
            + bytes((255,))
            + b"temp = 22.5 C"
        )
        self.assertEqual(
            msg2.encode(),
            binary2,
            "wrong encode operation for ACK message with payload, and Etag option",
        )
        msg2short = binary2[0:5] + binary2[10:]  # header, token, marker, data
        msg2a = copy.deepcopy(msg2)
        del msg2a.opt.etag
        self.assertEqual(
            msg2a.encode(), msg2short, "deleting single property did not succeed"
        )
        msg2b = copy.deepcopy(msg2)
        del msg2b.opt.etags
        self.assertEqual(
            msg2b.encode(), msg2short, "deleting list property did not succeed"
        )
        msg2c = copy.deepcopy(msg2)
        msg2c.opt.etags = []
        self.assertEqual(
            msg2c.encode(), msg2short, "emptying list property did not succeed"
        )
        msg2d = copy.deepcopy(msg2)
        msg2d.opt.etag = None
        self.assertEqual(
            msg2d.encode(), msg2short, "setting single property to None did not succeed"
        )

        msg3 = aiocoap.Message()
        self.assertRaises(TypeError, msg3.encode)

        msg4 = aiocoap.Message(_mtype=aiocoap.CON, _mid=2 << 16)
        self.assertRaises(Exception, msg4.encode)

        msg5 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)
        o = aiocoap.optiontypes.OpaqueOption(1234, value=b"abcd")
        msg5.opt.add_option(o)
        binary5 = binary1 + bytes((0xE4, 0x03, 0xC5)) + b"abcd"
        self.assertEqual(
            msg5.encode(), binary5, "wrong encoding for high option numbers"
        )

        msg6 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)
        o = aiocoap.optiontypes.OpaqueOption(12345678, value=b"abcd")
        msg6.opt.add_option(o)
        self.assertRaises(ValueError, msg6.encode)

        msg7 = aiocoap.Message(_mtype=aiocoap.CON, _mid=0, code=aiocoap.EMPTY)

        def set_unknown_opt():
            msg7.opt.foobar = 42

        self.assertRaises(AttributeError, set_unknown_opt)

    def test_decode(self):
        rawdata1 = bytes((64, 0, 0, 0))
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).mtype,
            aiocoap.CON,
            "wrong message type for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).mid,
            0,
            "wrong message ID for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).code,
            aiocoap.EMPTY,
            "wrong message code for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).token,
            b"",
            "wrong message token for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata1).payload,
            b"",
            "wrong message payload for decode operation",
        )
        rawdata2 = (
            bytes((97, 69, 188, 144, 113, 68))
            + b"abcd"
            + bytes((255,))
            + b"temp = 22.5 C"
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).mtype,
            aiocoap.ACK,
            "wrong message type for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).mid,
            0xBC90,
            "wrong message ID for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).code,
            aiocoap.CONTENT,
            "wrong message code for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).token,
            b"q",
            "wrong message token for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).payload,
            b"temp = 22.5 C",
            "wrong message payload for decode operation",
        )
        self.assertEqual(
            aiocoap.Message.decode(rawdata2).opt.etags,
            (b"abcd",),
            "problem with etag option decoding for decode operation",
        )
        self.assertEqual(
            len(aiocoap.Message.decode(rawdata2).opt._options),
            1,
            "wrong number of options after decode operation",
        )
        rawdata3 = rawdata1 + bytes((0xF0,))
        self.assertRaises(
            aiocoap.error.UnparsableMessage, aiocoap.Message.decode, rawdata3
        )  # message with option delta reserved for payload marker
        rawdata4 = rawdata1 + bytes((0xE0,))
        self.assertRaises(
            aiocoap.error.UnparsableMessage, aiocoap.Message.decode, rawdata4
        )  # message with extended option delta that is not actually there
        rawdata5 = rawdata1 + bytes((0x04,))
        self.assertRaises(
            aiocoap.error.UnparsableMessage, aiocoap.Message.decode, rawdata5
        )  # message with option that is not actually there


class TestReadExtendedFieldValue(unittest.TestCase):
    def test_read_extended_field_value(self):
        arguments = (
            (0, b"aaaa"),
            (0, b""),
            (1, b"aaaa"),
            (12, b"aaaa"),
            (13, b"aaaa"),
            (13, b"a"),
            (14, b"aaaa"),
            (14, b"aa"),
        )
        results = (
            (0, b"aaaa"),
            (0, b""),
            (1, b"aaaa"),
            (12, b"aaaa"),
            (110, b"aaa"),
            (110, b""),
            (25198, b"aa"),
            (25198, b""),
        )

        for argument, result in zip(arguments, results):
            self.assertEqual(
                aiocoap.options._read_extended_field_value(argument[0], argument[1]),
                result,
                "wrong result for value : "
                + repr(argument[0])
                + " , rawdata : "
                + repr(argument[1]),
            )


class TestUintOption(unittest.TestCase):
    def test_encode(self):
        arguments = (0, 1, 2, 40, 50, 255, 256, 1000)
        results = (
            b"",
            bytes((1,)),
            bytes((2,)),
            bytes((40,)),
            bytes((50,)),
            bytes((255,)),
            bytes((1, 0)),
            bytes((3, 232)),
        )
        for argument, result in zip(arguments, results):
            self.assertEqual(
                aiocoap.optiontypes.UintOption(0, argument).encode(),
                result,
                "wrong encode operation for option value : " + str(argument),
            )

    def test_decode(self):
        arguments = (
            b"",
            bytes((1,)),
            bytes((2,)),
            bytes((40,)),
            bytes((50,)),
            bytes((255,)),
            bytes((1, 0)),
            bytes((3, 232)),
        )
        results = (0, 1, 2, 40, 50, 255, 256, 1000)
        for argument, result in zip(arguments, results):
            o = aiocoap.optiontypes.UintOption(0)
            o.decode(argument)
            self.assertEqual(
                o.value, result, "wrong decode operation for rawdata : " + str(argument)
            )


class TestOptions(unittest.TestCase):
    def test_set_uri_path(self):
        opt1 = aiocoap.options.Options()
        opt1.uri_path = ["core"]
        self.assertEqual(
            len(opt1.get_option(aiocoap.OptionNumber.URI_PATH)),
            1,
            "wrong uri_path setter operation for single string argument",
        )
        self.assertEqual(
            opt1.get_option(aiocoap.OptionNumber.URI_PATH)[0].value,
            "core",
            "wrong uri_path setter operation for single string argument",
        )
        opt2 = aiocoap.options.Options()
        opt2.uri_path = ("core", ".well-known")
        self.assertEqual(
            len(opt2.get_option(aiocoap.OptionNumber.URI_PATH)),
            2,
            "wrong uri_path setter operation for 2-element tuple argument",
        )
        self.assertEqual(
            opt2.get_option(aiocoap.OptionNumber.URI_PATH)[0].value,
            "core",
            "wrong uri_path setter operation for 2-element tuple argument",
        )
        self.assertEqual(
            opt2.get_option(aiocoap.OptionNumber.URI_PATH)[1].value,
            ".well-known",
            "wrong uri_path setter operation for 2-element tuple argument",
        )
        opt3 = aiocoap.options.Options()
        self.assertRaises(TypeError, setattr, opt3, "uri_path", 42)


class TestOptiontypes(unittest.TestCase):
    def test_optiontypes(self):
        # from rfc725 table 4
        on = aiocoap.numbers.OptionNumber
        options = {
            on.IF_MATCH: "C",
            on.URI_HOST: "CU",
            on.ETAG: "",
            on.MAX_AGE: "U",
            on.SIZE1: "N",
        }

        for o, expected in options.items():
            self.assertEqual(
                "C" in expected, o.is_critical(), "Unexpected criticalness of %r" % o
            )
            self.assertEqual(
                "C" not in expected,
                o.is_elective(),
                "Unexpected electiveness of %r" % o,
            )
            self.assertEqual(
                "U" in expected, o.is_unsafe(), "Unexpected unsafeness of %r" % o
            )
            self.assertEqual(
                "U" not in expected,
                o.is_safetoforward(),
                "Unexpected safetoforwardness of %r" % o,
            )
            if o.is_safetoforward():
                self.assertEqual(
                    "N" in expected,
                    o.is_nocachekey(),
                    "Unexpected nocachekeyness of %r" % o,
                )
                self.assertEqual(
                    "N" not in expected,
                    o.is_cachekey(),
                    "Unexpected cachekeyness of %r" % o,
                )
            else:
                self.assertRaises(ValueError, o.is_nocachekey)
                self.assertRaises(ValueError, o.is_cachekey)


class TestMessageOptionConstruction(unittest.TestCase):
    def test_uri_construction(self):
        message = aiocoap.Message(uri="coap://some-host:1234/some/path/")
        self.assertEqual(message.opt.uri_host, "some-host")
        self.assertEqual(message.opt.uri_port, None)
        self.assertEqual(message.opt.uri_path, ("some", "path", ""))

    def test_opt_roundtripping(self):
        message = aiocoap.Message()
        message.opt.content_format = 40
        message.opt.etag = b"1234"
        message.opt.uri_path = ()
        self.assertEqual(message.opt.content_format, 40)
        self.assertEqual(message.opt.etag, b"1234")
        self.assertEqual(message.opt.uri_path, ())

    def test_opt_construction(self):
        message = aiocoap.Message(content_format=40, observe=b"1234", uri_path=())
        self.assertEqual(message.opt.content_format, 40)
        self.assertEqual(message.opt.observe, b"1234")
        self.assertEqual(message.opt.uri_path, ())

    def test_copy(self):
        message = aiocoap.Message()
        original_state = repr(message)
        new_one = message.copy(
            payload=b"x",
            mid=42,
            code=0,
            mtype=3,
            token=b"xyz",
            observe=0,
            content_format=1234,
        )
        self.assertEqual(original_state, repr(message), "Message.copy mutated original")
        self.assertEqual(new_one.payload, b"x")
        self.assertEqual(new_one.mid, 42)
        self.assertEqual(new_one.token, b"xyz")
        self.assertEqual(str(new_one.code), "EMPTY")
        # "Type.RST" is also ok if the enum decides to have a different str,
        # but it should be of mtype class and not just a number. Beware that
        # other tests also look for the string versions (eg. "ACK EMPTY")
        self.assertEqual(str(new_one.mtype), "RST")
        self.assertEqual(new_one.opt.observe, 0)
        self.assertEqual(new_one.opt.content_format, 1234)

        new_two = new_one.copy(uri="coap://some-host/some/path")
        self.assertEqual(new_two.opt.uri_path, ("some", "path"))
