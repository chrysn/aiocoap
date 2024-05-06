# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

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
    IF_MATCH: "OptionNumber" = 1  # type: ignore
    URI_HOST: "OptionNumber" = 3  # type: ignore
    ETAG: "OptionNumber" = 4  # type: ignore
    IF_NONE_MATCH: "OptionNumber" = 5  # type: ignore
    OBSERVE: "OptionNumber" = 6  # type: ignore
    URI_PORT: "OptionNumber" = 7  # type: ignore
    LOCATION_PATH: "OptionNumber" = 8  # type: ignore
    OSCORE: "OptionNumber" = 9  # type: ignore
    OSCORE: "OptionNumber" = 9  # type: ignore
    URI_PATH: "OptionNumber" = 11  # type: ignore
    CONTENT_FORMAT: "OptionNumber" = 12  # type: ignore
    MAX_AGE: "OptionNumber" = 14  # type: ignore
    URI_QUERY: "OptionNumber" = 15  # type: ignore
    HOP_LIMIT: "OptionNumber" = 16  # type: ignore
    ACCEPT: "OptionNumber" = 17  # type: ignore
    Q_BLOCK1: "OptionNumber" = 19  # type: ignore
    LOCATION_QUERY: "OptionNumber" = 20  # type: ignore
    EDHOC: "OptionNumber" = 21  # type: ignore
    BLOCK2: "OptionNumber" = 23  # type: ignore
    BLOCK1: "OptionNumber" = 27  # type: ignore
    SIZE2: "OptionNumber" = 28  # type: ignore
    Q_BLOCK2: "OptionNumber" = 31  # type: ignore
    PROXY_URI: "OptionNumber" = 35  # type: ignore
    PROXY_SCHEME: "OptionNumber" = 39  # type: ignore
    SIZE1: "OptionNumber" = 60  # type: ignore
    ECHO: "OptionNumber" = 252  # type: ignore
    NO_RESPONSE: "OptionNumber" = 258  # type: ignore
    REQUEST_TAG: "OptionNumber" = 292  # type: ignore

    # experimental for draft-amsuess-core-cachable-oscore
    #
    # Using the number suggested there (rather than a high one) as this is
    # going to be used in overhead comparisons.
    REQUEST_HASH: "OptionNumber" = 548  # type: ignore

    _deprecated_aliases = {
            "OBJECT_SECURITY": "OSCORE",
            }

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

    def _repr_html_(self):
        import html
        properties = f"{'critical' if self.is_critical() else 'elective'}, {'safe-to-forward' if self.is_safetoforward() else 'proxy unsafe'}"
        if self.is_safetoforward():
            properties += ", part of the cache key" if self.is_cachekey() else ", not part of the cache key"
        if hasattr(self, "name"):
            return f'<abbr title="option {int(self)}: {properties}">{html.escape(self.name)}</abbr>'
        else:
            return f'<abbr title="{properties}">Option {int(self)}</abbr>'

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
OptionNumber.CONTENT_FORMAT.format = optiontypes.ContentFormatOption
OptionNumber.MAX_AGE.format = optiontypes.UintOption
OptionNumber.URI_QUERY.format = optiontypes.StringOption
OptionNumber.ACCEPT.format = optiontypes.ContentFormatOption
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

OptionNumber.OSCORE.format = optiontypes.OpaqueOption

# RFC 9175

OptionNumber.ECHO.format = optiontypes.OpaqueOption
OptionNumber.REQUEST_TAG.format = optiontypes.OpaqueOption

# RFC 8768

OptionNumber.HOP_LIMIT.format = optiontypes.UintOption

# experimental for draft-amsuess-core-cachable-oscore

OptionNumber.REQUEST_HASH.format = optiontypes.OpaqueOption
