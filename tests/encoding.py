# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# txThings is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import struct

import aiocoap

import unittest

class TestMessage(unittest.TestCase):

    def test_encode(self):
        msg1 = aiocoap.Message(mtype=aiocoap.CON, mid=0)
        binary1 = bytes((64,0,0,0))
        self.assertEqual(msg1.encode(), binary1, "wrong encode operation for empty CON message")

        msg2 = aiocoap.Message(mtype=aiocoap.ACK, mid=0xBC90, code=aiocoap.CONTENT, payload=b"temp = 22.5 C", token=b'q')
        msg2.opt.etag = b"abcd"
        binary2 = bytes((97,69,188,144,113,68))+b"abcd"+bytes((255,))+b"temp = 22.5 C"
        self.assertEqual(msg2.encode(), binary2, "wrong encode operation for ACK message with payload, and Etag option")

        msg3 = aiocoap.Message()
        self.assertRaises(TypeError, msg3.encode)

    def test_decode(self):
        rawdata1 = bytes((64,0,0,0))
        self.assertEqual(aiocoap.Message.decode(rawdata1).mtype, aiocoap.CON, "wrong message type for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata1).mid, 0, "wrong message ID for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata1).code, aiocoap.EMPTY, "wrong message code for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata1).token, b'', "wrong message token for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata1).payload, b'', "wrong message payload for decode operation")
        rawdata2 = bytes((97,69,188,144,113,68))+b"abcd"+bytes((255,))+b"temp = 22.5 C"
        self.assertEqual(aiocoap.Message.decode(rawdata2).mtype, aiocoap.ACK, "wrong message type for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata2).mid, 0xBC90, "wrong message ID for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata2).code, aiocoap.CONTENT, "wrong message code for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata2).token, b'q', "wrong message token for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata2).payload, b'temp = 22.5 C', "wrong message payload for decode operation")
        self.assertEqual(aiocoap.Message.decode(rawdata2).opt.etags, (b"abcd",), "problem with etag option decoding for decode operation")
        self.assertEqual(len(aiocoap.Message.decode(rawdata2).opt._options), 1, "wrong number of options after decode operation")

class TestReadExtendedFieldValue(unittest.TestCase):

    def test_read_extended_field_value(self):
        arguments = ((0, b"aaaa"),
                     (0, b""),
                     (1, b"aaaa"),
                     (12,b"aaaa"),
                     (13,b"aaaa"),
                     (13,b"a"),
                     (14,b"aaaa"),
                     (14,b"aa"))
        results = ((0, b"aaaa"),
                   (0, b""),
                   (1, b"aaaa"),
                   (12,b"aaaa"),
                   (110,b"aaa"),
                   (110,b""),
                   (25198,b"aa"),
                   (25198,b""))

        for argument, result in zip(arguments, results):
            self.assertEqual(aiocoap.options._read_extended_field_value(argument[0], argument[1]), result,'wrong result for value : '+ repr(argument[0]) + ' , rawdata : ' + repr(argument[1]))

class TestUintOption(unittest.TestCase):

    def test_encode(self):
        arguments = (0,
                     1,
                     2,
                     40,
                     50,
                     255,
                     256,
                     1000)
        results =   (b"",
                     bytes((1,)),
                     bytes((2,)),
                     bytes((40,)),
                     bytes((50,)),
                     bytes((255,)),
                     bytes((1,0)),
                     bytes((3,232)))
        for argument, result in zip(arguments, results):
            self.assertEqual(aiocoap.optiontypes.UintOption(0,argument).encode(), result,'wrong encode operation for option value : '+ str(argument))

    def test_decode(self):
        arguments = ("",
                     bytes((1,)),
                     bytes((2,)),
                     bytes((40,)),
                     bytes((50,)),
                     bytes((255,)),
                     bytes((1,0)),
                     bytes((3,232)))
        results =   (0,
                     1,
                     2,
                     40,
                     50,
                     255,
                     256,
                     1000)
        for argument, result in zip(arguments, results):
            self.assertEqual(aiocoap.optiontypes.UintOption(0).decode(argument).value, result,'wrong decode operation for rawdata : '+ str(argument))

    def test_length(self):
        arguments = (0,
                     1,
                     2,
                     40,
                     50,
                     255,
                     256,
                     1000)
        results =   (0,
                     1,
                     1,
                     1,
                     1,
                     1,
                     2,
                     2)
        for argument, result in zip(arguments, results):
            self.assertEqual(aiocoap.optiontypes.UintOption(0,argument)._length(), result,'wrong length for option value : '+ str(argument))


class TestOptions(unittest.TestCase):

    def test_set_uri_path(self):
        opt1 = aiocoap.options.Options()
        opt1.uri_path = ["core"]
        self.assertEqual(len(opt1.get_option(aiocoap.OptionNumber.URI_PATH)), 1, 'wrong uri_path setter operation for single string argument')
        self.assertEqual(opt1.get_option(aiocoap.OptionNumber.URI_PATH)[0].value, "core", 'wrong uri_path setter operation for single string argument')
        opt2 = aiocoap.options.Options()
        opt2.uri_path = ("core",".well-known")
        self.assertEqual(len(opt2.get_option(aiocoap.OptionNumber.URI_PATH)), 2, 'wrong uri_path setter operation for 2-element tuple argument')
        self.assertEqual(opt2.get_option(aiocoap.OptionNumber.URI_PATH)[0].value, "core", 'wrong uri_path setter operation for 2-element tuple argument')
        self.assertEqual(opt2.get_option(aiocoap.OptionNumber.URI_PATH)[1].value, ".well-known", 'wrong uri_path setter operation for 2-element tuple argument')
        opt3 = aiocoap.options.Options()
        self.assertRaises(ValueError, setattr, opt3, "uri_path", "core")


