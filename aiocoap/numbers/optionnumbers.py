# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Known values for CoAP option numbers

The values defined in `OptionNumber` correspond to the IANA registry "CoRE
Parameters", subregistries "CoAP Method Codes" and "CoAP Response Codes".

The option numbers come with methods that can be used to evaluate their
properties, see the `OptionNumber` class for details.
"""

from ..util import ExtensibleIntEnum
from .. import optiontypes

#=============================================================================
# coap-18, block-14, observe-11
#=============================================================================
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# | No. | C | U | N | R | Name           | Format     | Length | Default     |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# |   1 | x |   |   | x | If-Match       | opaque     | 0-8    | (none)      |
# |   3 | x | x | - |   | Uri-Host       | string     | 1-255  | (see below) |
# |   4 |   |   |   | x | ETag           | opaque     | 1-8    | (none)      |
# |   5 | x |   |   |   | If-None-Match  | empty      | 0      | (none)      |
# |   6 |   | x |   |   | Observe        | empty/uint | ?      | (none)      |
# |   7 | x | x | - |   | Uri-Port       | uint       | 0-2    | (see below) |
# |   8 |   |   |   | x | Location-Path  | string     | 0-255  | (none)      |
# |  11 | x | x | - | x | Uri-Path       | string     | 0-255  | (none)      |
# |  12 |   |   |   |   | Content-Format | uint       | 0-2    | (none)      |
# |  14 |   | x |   |   | Max-Age        | uint       | 0-4    | 60          |
# |  15 | x | x | - | x | Uri-Query      | string     | 0-255  | (none)      |
# |  17 | x |   |   |   | Accept         | uint       | 0-2    | (none)      |
# |  20 |   |   |   | x | Location-Query | string     | 0-255  | (none)      |
# |  23 | x | x | - | - | Block2         | uint       | 0-3    | (see below) |
# |  27 | x | x | - | - | Block1         | uint       | 0-3    | (see below) |
# |  28 |   |   | x |   | Size2          | uint       | 0-4    | (none)      |
# |  35 | x | x | - |   | Proxy-Uri      | string     | 1-1034 | (none)      |
# |  39 | x | x | - |   | Proxy-Scheme   | string     | 1-255  | (none)      |
# |  60 |   |   | x |   | Size1          | uint       | 0-4    | (none)      |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
#=============================================================================
#
# This table should serve as a reference only. It does not confirm that
# txThings conforms to the documents above
#

class OptionNumber(ExtensibleIntEnum):
    """A CoAP option number.

    As the option number contains information on whether the option is
    critical, and whether it is safe-to-forward, those properties can be
    queried using the `is_*` group of methods.

    Note that whether an option may be repeated or not does not only depend on
    the option, but also on the context, and is thus handled in the `Options`
    object instead."""
    IF_MATCH = 1
    URI_HOST = 3
    ETAG = 4
    IF_NONE_MATCH = 5
    OBSERVE = 6
    URI_PORT = 7
    LOCATION_PATH = 8
    URI_PATH = 11
    CONTENT_FORMAT = 12
    MAX_AGE = 14
    URI_QUERY = 15
    ACCEPT = 17
    LOCATION_QUERY = 20
    BLOCK2 = 23
    BLOCK1 = 27
    SIZE2 = 28
    PROXY_URI = 35
    PROXY_SCHEME = 39
    SIZE1 = 60
    NO_RESPONSE = 258
    OBJECT_SECURITY = 21 # number used for the latest plug tests for draft-ietf-core-object-security

    def is_critical(self):
        return self & 0x01 == 0x01

    def is_elective(self):
        return not self.is_critical()

    def is_unsafe(self):
        return self & 0x02 == 0x02

    def is_safetoforward(self):
        return not self.is_unsafe()

    def is_nocachekey(self):
        if self.is_unsafe():
            raise ValueError("NoCacheKey is only meaningful for safe options")
        return self & 0x1e == 0x1c

    def is_cachekey(self):
        return not self.is_nocachekey()

    def _get_format(self):
        if hasattr(self, "_format"):
            return self._format
        else:
            return optiontypes.OpaqueOption

    def _set_format(self, value):
        self._format = value

    format = property(_get_format, _set_format)

    def create_option(self, decode=None, value=None):
        """Return an Option element of the appropriate class from this option
        number.

        An initial value may be set using the decode or value options, and will
        be fed to the resulting object's decode method or value property,
        respectively."""
        option = self.format(self)
        if decode is not None:
            option.decode(decode)
        if value is not None:
            option.value = value
        return option

# OpaqueOption is set on formats where it is known to be used even though it is
# the default. This allows developers to rely on those interfaces to be stable
# (or at least to be notified visibly in the release notes).

# RFC 7252

OptionNumber.IF_MATCH.format = optiontypes.OpaqueOption
OptionNumber.URI_HOST.format = optiontypes.StringOption
OptionNumber.ETAG.format = optiontypes.OpaqueOption
OptionNumber.URI_PORT.format = optiontypes.UintOption
OptionNumber.LOCATION_PATH.format = optiontypes.StringOption
OptionNumber.URI_PATH.format = optiontypes.StringOption
OptionNumber.CONTENT_FORMAT.format = optiontypes.UintOption
OptionNumber.MAX_AGE.format = optiontypes.UintOption
OptionNumber.URI_QUERY.format = optiontypes.StringOption
OptionNumber.ACCEPT.format = optiontypes.UintOption
OptionNumber.LOCATION_QUERY.format = optiontypes.StringOption
OptionNumber.PROXY_URI.format = optiontypes.StringOption
OptionNumber.PROXY_SCHEME.format = optiontypes.StringOption
OptionNumber.SIZE1.format = optiontypes.UintOption

# RFC 7959

OptionNumber.BLOCK2.format = optiontypes.BlockOption
OptionNumber.BLOCK1.format = optiontypes.BlockOption
OptionNumber.SIZE2.format = optiontypes.UintOption

# RFC 7641

OptionNumber.OBSERVE.format = optiontypes.UintOption

# RFC 7967

OptionNumber.NO_RESPONSE.format = optiontypes.UintOption

# draft-ietf-core-object-security

OptionNumber.OBJECT_SECURITY.format = optiontypes.OpaqueOption
