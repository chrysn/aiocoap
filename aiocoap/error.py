# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""
Exception definitions for txThings CoAP library.
"""

from .numbers import codes

class Error(Exception):
    """
    Base exception for all exceptions that indicate a failed request
    """

class RenderableError(Error):
    """
    Exception that can meaningfully be represented in a CoAP response
    """
    code = codes.INTERNAL_SERVER_ERROR
    message = ""

class NoResource(RenderableError):
    """
    Raised when resource is not found.
    """
    code = codes.NOT_FOUND
    message = "Error: Resource not found!"

class UnallowedMethod(RenderableError):
    """
    Raised by a resource when request method is understood by the server
    but not allowed for that particular resource.
    """
    code = codes.METHOD_NOT_ALLOWED
    message = "Error: Method not allowed!"

class UnsupportedMethod(RenderableError):
    """
    Raised when request method is not understood by the server at all.
    """
    code = codes.METHOD_NOT_ALLOWED
    message = "Error: Method not recognized!"

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

class UnexpectedBlock1Option(Error):
    """
    Raised when a server responds with block1 options that just don't match.
    """

class UnexpectedBlock2(Error):
    """
    Raised when a server responds with another block2 than expected.
    """

class MissingBlock2Option(Error):
    """
    Raised when response with Block2 option is expected
    (previous response had Block2 option with More flag set),
    but response without Block2 option is received.
    """

class NotObservable(Error):
    """
    The server did not accept the request to observe the resource.
    """

class ObservationCancelled(Error):
    """
    The server claimed that it will no longer sustain the observation.
    """

class UnparsableMessage(Error):
    """
    An incoming message does not look like CoAP.

    Note that this happens rarely -- the requirements are just two bit at the
    beginning of the message, and a minimum length.
    """

class CommunicationKilled(RenderableError):
    """
    The communication process has been aborted by request of the application.
    """
    code = codes.SERVICE_UNAVAILABLE
