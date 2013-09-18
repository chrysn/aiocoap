"""
Created on 08-09-2012

@author: Maciej Wasilak

Exception definitions for txThings CoAP library.
"""


#import iot.coap


class NoResource(Exception):
    """
    Raised when resource is not found.
    """


class UnallowedMethod(Exception):
    """
    Raised by a resource when request method is understood by the server
    but not allowed for that particular resource.
    """


class UnsupportedMethod(Exception):
    """
    Raised when request method is not understood by the server at all.
    """


class NotImplemented(Exception):
    """
    Raised when request is correct, but feature is not implemented
    by txThings library.
    For example non-sequential blockwise transfers
    """


class RequestTimedOut(Exception):
    """
    Raised when request is timed out.
    """


class WaitingForClientTimedOut(Exception):
    """
    Raised when server expects some client action:
        - sending next PUT/POST request with block1 or block2 option
        - sending next GET request with block2 option
    but client does nothing.
    """

__all__ = ['NoResource',
           'UnallowedMethod',
           'UnsupportedMethod',
           'NotImplemented',
           'RequestTimedOut']
