'''
Created on 16-10-2012

@author: Maciek
'''
from twisted.trial import unittest
import iot.coap as coap
import struct


class TestReadExtendedFieldValue(unittest.TestCase):

    def test_readExtendedFieldValue(self):
        arguments = ((0, "aaaa"),
                     (0, ""),
                     (1, "aaaa"),
                     (12,"aaaa"),
                     (13,"aaaa"),
                     (13,"a"),
                     (14,"aaaa"),
                     (14,"aa"))
        results = ((0, "aaaa"),
                   (0, ""), 
                   (1, "aaaa"),
                   (12,"aaaa"),
                   (110,"aaa"),
                   (110,""),
                   (25198,"aa"),
                   (25198,""))

        for argument, result in zip(arguments, results):
            self.assertEqual(coap.readExtendedFieldValue(argument[0], argument[1]), result,'wrong result for value : '+ str(argument[0]) + ' , rawdata : ' + argument[1])


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
        results =   ("",
                     chr(1),
                     chr(2),
                     chr(40),
                     chr(50),
                     chr(255),
                     chr(1)+chr(0),
                     chr(3)+chr(232))
        for argument, result in zip(arguments, results):
            self.assertEqual(coap.UintOption(0,argument).encode(), result,'wrong encode operation for option value : '+ str(argument))      
    
    def test_decode(self):
        arguments = ("",
                     chr(1),
                     chr(2),
                     chr(40),
                     chr(50),
                     chr(255),
                     chr(1)+chr(0),
                     chr(3)+chr(232))
        results =   (0,
                     1,
                     2,
                     40,
                     50,
                     255,
                     256,
                     1000)
        for argument, result in zip(arguments, results):
            self.assertEqual(coap.UintOption(0).decode(argument).value, result,'wrong decode operation for rawdata : '+ str(argument))      
    
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
            self.assertEqual(coap.UintOption(0,argument)._length(), result,'wrong length for option value : '+ str(argument))


class TestOptions(unittest.TestCase):
                
    def test_setUriPath(self):
        opt1 = coap.Options()
        opt1.uri_path = ["core"]
        self.assertEqual(len(opt1.getOption(coap.URI_PATH)), 1, 'wrong uri_path setter operation for single string argument')
        self.assertEqual(opt1.getOption(coap.URI_PATH)[0].value, "core", 'wrong uri_path setter operation for single string argument')
        opt2 = coap.Options()
        opt2.uri_path = ("core",".well-known")
        self.assertEqual(len(opt2.getOption(coap.URI_PATH)), 2, 'wrong uri_path setter operation for 2-element tuple argument')
        self.assertEqual(opt2.getOption(coap.URI_PATH)[0].value, "core", 'wrong uri_path setter operation for 2-element tuple argument')
        self.assertEqual(opt2.getOption(coap.URI_PATH)[1].value, ".well-known", 'wrong uri_path setter operation for 2-element tuple argument')             
        opt3 = coap.Options()
        self.assertRaises(ValueError, setattr, opt3, "uri_path", "core")
                                
                