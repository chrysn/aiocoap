# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""
Common errors for the aiocoap library
"""

import warnings
import abc
import errno

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
        return "<%s: %s %r>" % (
            type(self).__name__,
            self.coapmessage.code,
            self.coapmessage.payload,
        )


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

        return Message(code=self.code, payload=self.message.encode("utf8"))

    code = codes.INTERNAL_SERVER_ERROR  #: Code assigned to messages built from it
    message = ""  #: Text sent in the built message's payload


# This block is code-generated to make the types available to static checkers.
# The __debug__ check below ensures that it stays up to date.
class BadRequest(ConstructionRenderableError):
    code = codes.BAD_REQUEST


class Unauthorized(ConstructionRenderableError):
    code = codes.UNAUTHORIZED


class BadOption(ConstructionRenderableError):
    code = codes.BAD_OPTION


class Forbidden(ConstructionRenderableError):
    code = codes.FORBIDDEN


class NotFound(ConstructionRenderableError):
    code = codes.NOT_FOUND


class MethodNotAllowed(ConstructionRenderableError):
    code = codes.METHOD_NOT_ALLOWED


class NotAcceptable(ConstructionRenderableError):
    code = codes.NOT_ACCEPTABLE


class RequestEntityIncomplete(ConstructionRenderableError):
    code = codes.REQUEST_ENTITY_INCOMPLETE


class Conflict(ConstructionRenderableError):
    code = codes.CONFLICT


class PreconditionFailed(ConstructionRenderableError):
    code = codes.PRECONDITION_FAILED


class RequestEntityTooLarge(ConstructionRenderableError):
    code = codes.REQUEST_ENTITY_TOO_LARGE


class UnsupportedContentFormat(ConstructionRenderableError):
    code = codes.UNSUPPORTED_CONTENT_FORMAT


class UnprocessableEntity(ConstructionRenderableError):
    code = codes.UNPROCESSABLE_ENTITY


class TooManyRequests(ConstructionRenderableError):
    code = codes.TOO_MANY_REQUESTS


class InternalServerError(ConstructionRenderableError):
    code = codes.INTERNAL_SERVER_ERROR


class NotImplemented(ConstructionRenderableError):
    code = codes.NOT_IMPLEMENTED


class BadGateway(ConstructionRenderableError):
    code = codes.BAD_GATEWAY


class ServiceUnavailable(ConstructionRenderableError):
    code = codes.SERVICE_UNAVAILABLE


class GatewayTimeout(ConstructionRenderableError):
    code = codes.GATEWAY_TIMEOUT


class ProxyingNotSupported(ConstructionRenderableError):
    code = codes.PROXYING_NOT_SUPPORTED


class HopLimitReached(ConstructionRenderableError):
    code = codes.HOP_LIMIT_REACHED


if __debug__:
    _missing_codes = False
    _full_code = ""
    for code in codes.Code:
        if code.is_successful() or not code.is_response():
            continue
        classname = "".join(w.title() for w in code.name.split("_"))
        _full_code += f"""
class {classname}(ConstructionRenderableError):
    code = codes.{code.name}"""
        if classname not in locals():
            warnings.warn(f"Missing exception type: f{classname}")
            _missing_codes = True
            continue
        if locals()[classname].code != code:
            warnings.warn(
                f"Mismatched code for {classname}: Should be {code}, is {locals()[classname].code}"
            )
            _missing_codes = True
            continue
    if _missing_codes:
        warnings.warn(
            "Generated exception list is out of sync, should be:\n" + _full_code
        )

# More detailed versions of code based errors


class NoResource(NotFound):
    """
    Raised when resource is not found.
    """

    message = "Error: Resource not found!"

    def __init__(self):
        warnings.warn(
            "NoResource is deprecated in favor of NotFound",
            DeprecationWarning,
            stacklevel=2,
        )


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

    def extra_help(self):
        """Information printed at aiocoap-client or similar occasions when the
        error message itself may be insufficient to point the user in the right
        direction"""
        if isinstance(self.__cause__, OSError):
            if self.__cause__.errno == errno.ECONNREFUSED:
                # seen trying to reach any used address with the port closed
                return "The remote host could be reached, but reported that the requested port is not open. Check whether a CoAP server is running at the address, or whether it is running on a different port."
            if self.__cause__.errno == errno.EHOSTUNREACH:
                # seen trying to reach any unused local address
                return "No way of contacting the remote host could be found. This could be because a host on the local network is offline or firewalled. Tools for debugging in the next step could be ping or traceroute."
            if self.__cause__.errno == errno.ENETUNREACH:
                # seen trying to reach an IPv6 host through an IP literal from a v4-only system, or trying to reach 2001:db8::1
                return "No way of contacting the remote network could be found. This may be due to lack of IPv6 connectivity, lack of a concrete route (eg. trying to reach a private use network which there is no route to). Tools for debugging in the next step could be ping or traceroute."
            if self.__cause__.errno == errno.EACCES:
                # seen trying to reach the broadcast address of a local network
                return "The operating system refused to send the request. For example, this can occur when attempting to send broadcast requests instead of multicast requests."


class ResolutionError(NetworkError):
    """Resolving the host component of a URI to a usable transport address was
    not possible"""


class MessageError(NetworkError):
    """Received an error from the remote on the CoAP message level (typically a
    RST)"""


class RemoteServerShutdown(NetworkError):
    """The peer a request was sent to in a stateful connection closed the
    connection around the time the request was sent"""


class TimeoutError(NetworkError):
    """Base for all timeout-ish errors.

    Like NetworkError, receiving this alone does not indicate whether the
    request may have reached the server or not.
    """

    def extra_help(self):
        return "Neither a response nor an error was received. This can have a wide range of causes, from the address being wrong to the server being stuck."


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


__getattr__ = util.deprecation_getattr(
    {
        "UnsupportedMediaType": "UnsupportedContentFormat",
        "RequestTimedOut": "TimeoutError",
        "WaitingForClientTimedOut": "TimeoutError",
    },
    globals(),
)
