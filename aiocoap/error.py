# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""
Common errors for the aiocoap library
"""

import warnings
import abc

from .numbers import codes

class Error(Exception):
    """
    Base exception for all exceptions that indicate a failed request
    """

class RenderableError(Error, metaclass=abc.ABCMeta):
    """
    Exception that can meaningfully be represented in a CoAP response
    """

    @abc.abstractmethod
    def to_message(self):
        """Create a CoAP message that should be sent when this exception is
        rendered"""

class ResponseWrappingError(Error):
    """
    An exception that is raised due to an unsuccessful but received response.

    A better relationship with :mod:`.numbers.codes` should be worked out to do
    ``except UnsupportedMediaType`` (similar to the various ``OSError``
    subclasses).
    """
    def __init__(self, coapmessage):
        self.coapmessage = coapmessage

    def to_message(self):
        return self.coapmessage

    def __repr__(self):
        return "<%s: %s %r>"%(type(self).__name__, self.coapmessage.code, self.coapmessage.payload)

class ConstructionRenderableError(RenderableError):
    """
    RenderableError that is constructed from class attributes :attr:`code` and
    :attr:`message` (where the can be overridden in the constructor).
    """

    def __init__(self, message=None):
        if message is not None:
            self.message = message

    def to_message(self):
        from .message import Message
        return Message(code=self.code, payload=self.message.encode('utf8'))

    code = codes.INTERNAL_SERVER_ERROR #: Code assigned to messages built from it
    message = "" #: Text sent in the built message's payload

# FIXME: this should be comprehensive, maybe generted from the code list

class NotFound(ConstructionRenderableError):
    code = codes.NOT_FOUND

class MethodNotAllowed(ConstructionRenderableError):
    code = codes.METHOD_NOT_ALLOWED

class UnsupportedContentFormat(ConstructionRenderableError):
    code = codes.UNSUPPORTED_CONTENT_FORMAT

class Unauthorized(ConstructionRenderableError):
    code = codes.UNAUTHORIZED

class BadRequest(ConstructionRenderableError):
    code = codes.BAD_REQUEST

# More detailed versions of code based errors

class NoResource(NotFound):
    """
    Raised when resource is not found.
    """
    message = "Error: Resource not found!"
    def __init__(self):
        warnings.warn("NoResource is deprecated in favor of NotFound", DeprecationWarning, stacklevel=2)

class UnallowedMethod(MethodNotAllowed):
    """
    Raised by a resource when request method is understood by the server
    but not allowed for that particular resource.
    """
    message = "Error: Method not allowed!"

class UnsupportedMethod(MethodNotAllowed):
    """
    Raised when request method is not understood by the server at all.
    """
    message = "Error: Method not recognized!"


class NotImplemented(Error):
    """
    Raised when request is correct, but feature is not implemented
    by library.
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

class LibraryShutdown(Error):
    """The library or a transport registered with it was requested to shut
    down; this error is raised in all outstanding requests."""

class AnonymousHost(Error):
    """This is raised when it is attempted to express as a reference a (base)
    URI of a host or a resource that can not be reached by any process other
    than this.

    Typically, this happens when trying to serialize a link to a resource that
    is hosted on a CoAP-over-TCP or -WebSockets client: Such resources can be
    accessed for as long as the connection is active, but can not be used any
    more once it is closed or even by another system."""

class NetworkError(Error):
    """Base class for all "something went wrong with name resolution, sending
    or receiving packages".

    Errors of these kinds are raised towards client callers when things went
    wrong network-side, or at context creation. They are often raised from
    socket.gaierror or similar classes, but these are wrapped in order to make
    catching them possible independently of the underlying transport."""

class ResolutionError(NetworkError):
    """Resolving the host component of a URI to a usable transport address was
    not possible"""

class MessageError(NetworkError):
    """Received an error from the remote on the CoAP message level (typically a
    RST)"""

_deprecated_aliases = {
        "UnsupportedMediaType": "UnsupportedContentFormat",
        }
def __getattr__(name):
    if name in _deprecated_aliases:
        modern = _deprecated_aliases[name]
        from warnings import warn
        warn(f"{name} is deprecated, use {modern} instead", DeprecationWarning,
                stacklevel=2)
        return globals()[modern]
    raise AttributeError(f"module {__name__} has no attribute {name}")
