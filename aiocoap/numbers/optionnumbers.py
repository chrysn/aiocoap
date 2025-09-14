# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Known values for CoAP option numbers

The values defined in `OptionNumber` correspond to the IANA registry "CoRE
Parameters", subregistries "CoAP Method Codes" and "CoAP Response Codes".

The option numbers come with methods that can be used to evaluate their
properties, see the `OptionNumber` class for details.
"""

import warnings

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
    OSCORE = 9
    URI_PATH = 11
    CONTENT_FORMAT = 12
    MAX_AGE = 14
    URI_QUERY = 15
    HOP_LIMIT = 16
    ACCEPT = 17
    Q_BLOCK1 = 19
    LOCATION_QUERY = 20
    EDHOC = 21
    BLOCK2 = 23
    BLOCK1 = 27
    SIZE2 = 28
    Q_BLOCK2 = 31
    PROXY_URI = 35
    PROXY_SCHEME = 39
    SIZE1 = 60
    ECHO = 252
    NO_RESPONSE = 258
    REQUEST_TAG = 292

    # experimental for draft-amsuess-core-cachable-oscore
    #
    # Using the number suggested there (rather than a high one) as this is
    # going to be used in overhead comparisons.
    REQUEST_HASH = 548

    @property
    def OBJECT_SECURITY(self):
        warnings.warn("OBJECT_SECURITY is a deprecated alias for OSCORE")
        return self.OSCORE

    def __add__(self, delta):
        """Addition makes sense on these due to the delta encoding in CoAP
        serialization"""
        return type(self)(int(self) + delta)

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
        return self & 0x1E == 0x1C

    def is_cachekey(self):
        return not self.is_nocachekey()

    def _get_format(self):
        if hasattr(self, "_format"):
            return self._format
        else:
            return optiontypes.OpaqueOption

    def set_format(self, value):
        """Set the serialization format.

        This affects any use of the option throughout the program; existing
        options should not be altered incompatibly. Use this on custom or
        experimental options.

        This is available as a setter function in addition to write access
        through the `format` property to satisfy requirements imposed by mypy's
        special handling of enums.
        """
        if hasattr(self, "_format"):
            if self._format != value:
                warnings.warn(
                    "Altering the serialization format of {self}. This is a severe interoperability hazard with other modules, and should only be used during experimentation. This warning may be converted into an error at any time."
                )
        self._format = value

    format = property(
        _get_format,
        set_format,
        doc="Serialization format; see :func:`~aiocoap.numbers.optionnumbers.OptionNumber.set_format`",
    )

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

    @property
    def name_printable(self):
        """The name of the code in human-readable form

        This is only available on options that have a known name."""
        return self.name.replace("_", " ").title().replace(" ", "-")

    def _repr_html_(self):
        import html

        properties = f"{'critical' if self.is_critical() else 'elective'}, {'safe-to-forward' if self.is_safetoforward() else 'proxy unsafe'}"
        if self.is_safetoforward():
            properties += (
                ", part of the cache key"
                if self.is_cachekey()
                else ", not part of the cache key"
            )
        if hasattr(self, "name"):
            return f'<abbr title="option {int(self)}: {properties}">{html.escape(self.name_printable)}</abbr>'
        else:
            return f'<abbr title="{properties}">Option {int(self)}</abbr>'


# OpaqueOption is set on formats where it is known to be used even though it is
# the default. This allows developers to rely on those interfaces to be stable
# (or at least to be notified visibly in the release notes).

# RFC 7252

OptionNumber.IF_MATCH.set_format(optiontypes.OpaqueOption)
OptionNumber.URI_HOST.set_format(optiontypes.StringOption)
OptionNumber.ETAG.set_format(optiontypes.OpaqueOption)
OptionNumber.URI_PORT.set_format(optiontypes.UintOption)
OptionNumber.LOCATION_PATH.set_format(optiontypes.StringOption)
OptionNumber.URI_PATH.set_format(optiontypes.StringOption)
OptionNumber.CONTENT_FORMAT.set_format(optiontypes.ContentFormatOption)
OptionNumber.MAX_AGE.set_format(optiontypes.UintOption)
OptionNumber.URI_QUERY.set_format(optiontypes.StringOption)
OptionNumber.ACCEPT.set_format(optiontypes.ContentFormatOption)
OptionNumber.LOCATION_QUERY.set_format(optiontypes.StringOption)
OptionNumber.PROXY_URI.set_format(optiontypes.StringOption)
OptionNumber.PROXY_SCHEME.set_format(optiontypes.StringOption)
OptionNumber.SIZE1.set_format(optiontypes.UintOption)

# RFC 7959

OptionNumber.BLOCK2.set_format(optiontypes.BlockOption)
OptionNumber.BLOCK1.set_format(optiontypes.BlockOption)
OptionNumber.SIZE2.set_format(optiontypes.UintOption)

# RFC 7641

OptionNumber.OBSERVE.set_format(optiontypes.UintOption)

# RFC 7967

OptionNumber.NO_RESPONSE.set_format(optiontypes.UintOption)

# RFC 8613

OptionNumber.OSCORE.set_format(optiontypes.OpaqueOption)

# RFC 9175

OptionNumber.ECHO.set_format(optiontypes.OpaqueOption)
OptionNumber.REQUEST_TAG.set_format(optiontypes.OpaqueOption)

# RFC 8768

OptionNumber.HOP_LIMIT.set_format(optiontypes.UintOption)

# experimental for draft-amsuess-core-cachable-oscore

OptionNumber.REQUEST_HASH.set_format(optiontypes.OpaqueOption)
