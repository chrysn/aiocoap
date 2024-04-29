# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""
Common errors for the aiocoap library
"""

import warnings
import abc

from .numbers import codes
from . import util

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
        return "<%s: %s %r>" % (type(self).__name__, self.coapmessage.code, self.coapmessage.payload)

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

# generate error classes for all known error codes
for code in codes.Code.__dict__.values():
    if not isinstance(code, codes.Code):
        continue
    if code.is_successful() or not code.is_response():
        continue
    name = "".join(w.title() for w in code.name.split("_"))
    # Just to be safe, in case an attacker is able to insert arbitrary strings into the list of codes
    assert code.name.isidentifier() and name.isidentifier()
    src = f"""
class {name}(ConstructionRenderableError):
    code = codes.{code.name}
 """
    exec(src)
del code, name, src

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

class NotImplemented(Error):
    """
    Raised when request is correct, but feature is not implemented
    by library.
    For example non-sequential blockwise transfers
    """

class RemoteServerShutdown(NetworkError):
    """The peer a request was sent to in a stateful connection closed the
    connection around the time the request was sent"""

class TimeoutError(NetworkError):
    """Base for all timeout-ish errors.

    Like NetworkError, receiving this alone does not indicate whether the
    request may have reached the server or not.
    """

class ConRetransmitsExceeded(TimeoutError):
    """A transport that retransmits CON messages has failed to obtain a response
    within its retransmission timeout.

    When this is raised in a transport, requests failing with it may or may
    have been received by the server.
    """

class RequestTimedOut(TimeoutError):
    """
    Raised when request is timed out.

    This error is currently not produced by aiocoap; it is deprecated. Users
    can now catch error.TimeoutError, or newer more detailed subtypes
    introduced later.
    """


class WaitingForClientTimedOut(TimeoutError):
    """
    Raised when server expects some client action:

        - sending next PUT/POST request with block1 or block2 option
        - sending next GET request with block2 option

    but client does nothing.

    This error is currently not produced by aiocoap; it is deprecated. Users
    can now catch error.TimeoutError, or newer more detailed subtypes
    introduced later.
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

__getattr__ = util.deprecation_getattr({
        "UnsupportedMediaType": "UnsupportedContentFormat",
        "RequestTimedOut": "TimeoutError",
        "WaitingForClientTimedOut": "TimeoutError",
        }, globals())
