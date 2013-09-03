# -*- test-case-name: twisted.web.test.test_error -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Exception definitions for L{twisted.web}.
"""

import operator, warnings

#import iot.coap


class CoAPError(Exception):
    """
    A basic CoAP error.

    @type status: C{str}
    @ivar status: Refers to an HTTP status code, for example L{http.NOT_FOUND}.

    @type message: C{str}
    @param message: A short error message, for example "NOT FOUND".

    @type response: C{str}
    @ivar response: A complete HTML document for an error page.
    """
    def __init__(self, code, message=None, response=None):
        """
        Initializes a basic exception.

        @type code: C{str}
        @param code: Refers to an HTTP status code, for example
            L{http.NOT_FOUND}. If no C{message} is given, C{code} is mapped to a
            descriptive string that is used instead.

        @type message: C{str}
        @param message: A short error message, for example "NOT FOUND".

        @type response: C{str}
        @param response: A complete HTML document for an error page.
        """
        if not message:
            try:
                message = http.responses.get(int(code))
            except ValueError:
                # If code wasn't a stringified int, can't map the
                # status code to a descriptive string so keep message
                # unchanged.
                pass

        Exception.__init__(self, code, message, response)
        self.status = code
        self.message = message
        self.response = response


    def __str__(self):
        return '%s %s' % (self[0], self[1])



class UnallowedMethod(Exception):
    """
    Raised by a resource when request method is understood by the server 
    but not allowed for that particular resource.
    """

class UnsupportedMethod(Exception):
    """
    Raised when request method is not understood by the server at all.
    """


__all__ = [
    'Error', 'UnallowedMethod', 'UnsupportedMethod'
]
