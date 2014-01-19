"""
Created on 08-09-2012

@author: Maciej Wasilak

Exception definitions for txThings CoAP library.
"""


#import iot.coap

class Error(Exception):
    """
    Base exception for all exceptions that indicate a failed request
    """

class NoResource(Error):
    """
    Raised when resource is not found.
    """


class UnallowedMethod(Error):
    """
    Raised by a resource when request method is understood by the server
    but not allowed for that particular resource.
    """


class UnsupportedMethod(Error):
    """
    Raised when request method is not understood by the server at all.
    """


class NotImplemented(Error):
    """
    Raised when request is correct, but feature is not implemented
    by txThings library.
    For example non-sequential blockwise transfers
    """


class RequestTimedOut(Error):
    """
    Raised when request is timed out.
    """


class WaitingForClientTimedOut(Error):
    """
    Raised when server expects some client action:
        - sending next PUT/POST request with block1 or block2 option
        - sending next GET request with block2 option
    but client does nothing.
    """

class ResourceChanged(Error):
    """
    The requested resource was modified during the request and could therefore
    not be received in a consistent state.
    """

class MissingBlock2Option(Error):
    """
    Raised when response with Block2 option is expected 
    (previous response had Block2 option with More flag set),
    but response without Block2 option is received.
    """

__all__ = ['Error',
           'NoResource',
           'UnallowedMethod',
           'UnsupportedMethod',
           'NotImplemented',
           'RequestTimedOut',
           'ResourceChanged']
