# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""List of known values for the CoAP "Code" field.

The values in this module correspond to the IANA registry "`CoRE Parameters`_",
subregistries "CoAP Method Codes" and "CoAP Response Codes".

The codes come with methods that can be used to get their rough meaning, see
the :class:`Code` class for details.

.. _`CoRE Parameters`: https://www.iana.org/assignments/core-parameters/core-parameters.xhtml
"""

import warnings

from ..util import ExtensibleIntEnum


class Code(ExtensibleIntEnum):
    """Value for the CoAP "Code" field.

    As the number range for the code values is separated, the rough meaning of
    a code can be determined using the :meth:`is_request`, :meth:`is_response` and
    :meth:`is_successful` methods."""

    EMPTY = 0
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4
    FETCH = 5
    PATCH = 6
    iPATCH = 7
    CREATED = 65
    DELETED = 66
    VALID = 67
    CHANGED = 68
    CONTENT = 69
    CONTINUE = 95
    BAD_REQUEST = 128
    UNAUTHORIZED = 129
    BAD_OPTION = 130
    FORBIDDEN = 131
    NOT_FOUND = 132
    METHOD_NOT_ALLOWED = 133
    NOT_ACCEPTABLE = 134
    REQUEST_ENTITY_INCOMPLETE = 136
    CONFLICT = (4 << 5) + 9
    PRECONDITION_FAILED = 140
    REQUEST_ENTITY_TOO_LARGE = 141
    UNSUPPORTED_CONTENT_FORMAT = 143

    @property
    def UNSUPPORTED_MEDIA_TYPE(self):
        warnings.warn(
            "UNSUPPORTED_MEDIA_TYPE is a deprecated alias for UNSUPPORTED_CONTENT_FORMAT"
        )
        return self.UNSUPPORTED_CONTENT_FORMAT

    UNPROCESSABLE_ENTITY = (4 << 5) + 22
    TOO_MANY_REQUESTS = (4 << 5) + 29
    INTERNAL_SERVER_ERROR = 160
    NOT_IMPLEMENTED = 161
    BAD_GATEWAY = 162
    SERVICE_UNAVAILABLE = 163
    GATEWAY_TIMEOUT = 164
    PROXYING_NOT_SUPPORTED = 165
    HOP_LIMIT_REACHED = (5 << 5) + 8

    CSM = 225
    PING = 226
    PONG = 227
    RELEASE = 228
    ABORT = 229

    def is_request(self):
        """True if the code is in the request code range"""
        return True if (self >= 1 and self < 32) else False

    def is_response(self):
        """True if the code is in the response code range"""
        return True if (self >= 64 and self < 192) else False

    def is_signalling(self):
        return True if self >= 224 else False

    def is_successful(self):
        """True if the code is in the successful subrange of the response code range"""
        return True if (self >= 64 and self < 96) else False

    def can_have_payload(self):
        """True if a message with that code can carry a payload. This is not
        checked for strictly, but used as an indicator."""
        return self.is_response() or self in (
            self.POST,
            self.PUT,
            self.FETCH,
            self.PATCH,
            self.iPATCH,
        )

    @property
    def class_(self):
        """The class of a code (distinguishing whether it's successful, a
        request or a response error or more).

        >>> Code.CONTENT
        <Successful Response Code 69 "2.05 Content">
        >>> Code.CONTENT.class_
        2
        >>> Code.BAD_GATEWAY
        <Response Code 162 "5.02 Bad Gateway">
        >>> Code.BAD_GATEWAY.class_
        5
        """
        return self >> 5

    @property
    def dotted(self):
        """The numeric value three-decimal-digits (c.dd) form"""
        return "%d.%02d" % divmod(self, 32)

    @property
    def name_printable(self):
        """The name of the code in human-readable form"""
        return self.name.replace("_", " ").title()

    def __str__(self):
        """
        >>> print(Code.GET)
        GET
        >>> print(Code.CONTENT)
        2.05 Content
        >>> print(Code.BAD_GATEWAY)
        5.02 Bad Gateway
        >>> print(Code(32))
        32
        """
        if self.is_request() or self is self.EMPTY:
            return self.name
        elif self.is_response() or self.is_signalling():
            return "%s %s" % (self.dotted, self.name_printable)
        else:
            return "%d" % self

    def _classification(self):
        return ("Successful " if self.is_successful() else "") + (
            "Request "
            if self.is_request()
            else "Response "
            if self.is_response()
            else ""
        )

    def __repr__(self):
        """
        >>> Code.GET
        <Request Code 1 "GET">
        >>> Code.CONTENT
        <Successful Response Code 69 "2.05 Content">
        >>> Code.BAD_GATEWAY
        <Response Code 162 "5.02 Bad Gateway">
        >>> Code(32)
        <Code 32 "32">
        """
        return '<%sCode %d "%s">' % (self._classification(), self, self)

    def _repr_html_(self):
        """
        >>> Code.GET._repr_html_()
        '<abbr title="Request Code 0.01">GET</abbr>'
        >>> Code(31)._repr_html_()
        '<abbr title="Unknown Request Code">0.31</abbr>'
        """
        import html

        if self.name == "(unknown)":
            return f'<abbr title="Unknown {self._classification()}Code">{self.dotted}</abbr>'
        else:
            return f'<abbr title="{self._classification()}Code {self.dotted}">{html.escape(self.name)}</abbr>'

    @classmethod
    def _missing_(cls, value):
        constructed = super()._missing_(value)
        constructed._name_ = "(unknown)"
        return constructed


# List is copied down to help mypy and other typing dependent tools to
# understand the types.
EMPTY = Code.EMPTY
GET = Code.GET
POST = Code.POST
PUT = Code.PUT
DELETE = Code.DELETE
FETCH = Code.FETCH
PATCH = Code.PATCH
iPATCH = Code.iPATCH
CREATED = Code.CREATED
DELETED = Code.DELETED
VALID = Code.VALID
CHANGED = Code.CHANGED
CONTENT = Code.CONTENT
CONTINUE = Code.CONTINUE
BAD_REQUEST = Code.BAD_REQUEST
UNAUTHORIZED = Code.UNAUTHORIZED
BAD_OPTION = Code.BAD_OPTION
FORBIDDEN = Code.FORBIDDEN
NOT_FOUND = Code.NOT_FOUND
METHOD_NOT_ALLOWED = Code.METHOD_NOT_ALLOWED
NOT_ACCEPTABLE = Code.NOT_ACCEPTABLE
REQUEST_ENTITY_INCOMPLETE = Code.REQUEST_ENTITY_INCOMPLETE
CONFLICT = Code.CONFLICT
PRECONDITION_FAILED = Code.PRECONDITION_FAILED
REQUEST_ENTITY_TOO_LARGE = Code.REQUEST_ENTITY_TOO_LARGE
UNSUPPORTED_CONTENT_FORMAT = Code.UNSUPPORTED_CONTENT_FORMAT
UNPROCESSABLE_ENTITY = Code.UNPROCESSABLE_ENTITY
TOO_MANY_REQUESTS = Code.TOO_MANY_REQUESTS
INTERNAL_SERVER_ERROR = Code.INTERNAL_SERVER_ERROR
NOT_IMPLEMENTED = Code.NOT_IMPLEMENTED
BAD_GATEWAY = Code.BAD_GATEWAY
SERVICE_UNAVAILABLE = Code.SERVICE_UNAVAILABLE
GATEWAY_TIMEOUT = Code.GATEWAY_TIMEOUT
PROXYING_NOT_SUPPORTED = Code.PROXYING_NOT_SUPPORTED
HOP_LIMIT_REACHED = Code.HOP_LIMIT_REACHED
CSM = Code.CSM
PING = Code.PING
PONG = Code.PONG
RELEASE = Code.RELEASE
ABORT = Code.ABORT
if __debug__:
    for _code in Code:
        if locals().get(_code.name) is not _code:
            warnings.warn(
                f"Locals list is out of sync; entry `{_code.name} = Code.{_code.name}` is missing"
            )


__all__ = ["Code"] + [
    k for (k, v) in locals().items() if isinstance(v, Code) and not k.startswith("_")
]
