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
    OBJECT_SECURITY = 9
    # picked for draft-ietf-core-echo-request-tag-09
    ECHO = 252
    REQUEST_TAG = 292

    # experimental for draft-amsuess-core-cachable-oscore
    #
    # Using the number suggested there (rather than a high one) as this is
    # going to be used in overhead comparisons.
    REQUEST_HASH = 548

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

# RFC 8613

OptionNumber.OBJECT_SECURITY.format = optiontypes.OpaqueOption

# draft-ietf-core-echo-request-tag

OptionNumber.ECHO.format = optiontypes.OpaqueOption
OptionNumber.REQUEST_TAG.format = optiontypes.OpaqueOption

# experimental for draft-amsuess-core-cachable-oscore

OptionNumber.REQUEST_HASH.format = optiontypes.OpaqueOption
