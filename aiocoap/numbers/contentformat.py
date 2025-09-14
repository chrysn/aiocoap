# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Module containing the CoRE parameters / CoAP Content-Formats registry"""

from __future__ import annotations

from typing import Dict, Tuple

from ..util import ExtensibleIntEnum, ExtensibleEnumMeta
import warnings

# _raw can be updated from: `curl https://www.iana.org/assignments/core-parameters/content-formats.csv | python3 -c 'import csv, sys; print(list(csv.reader(sys.stdin))[1:])'`

# fmt: off
_raw = [
        ['text/plain; charset=utf-8', '', '0', '[RFC2046][RFC3676][RFC5147]'],
        ['Unassigned', '', '1-15', ''],
        ['application/cose; cose-type="cose-encrypt0"', '', '16', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/cose; cose-type="cose-mac0"', '', '17', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/cose; cose-type="cose-sign1"', '', '18', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/ace+cbor', '', '19', '[RFC-ietf-ace-oauth-authz-46]'],
        ['Unassigned', '', '20', ''],
        ['image/gif', '', '21', '[https://www.w3.org/Graphics/GIF/spec-gif89a.txt]'],
        ['image/jpeg', '', '22', '[ISO/IEC 10918-5]'],
        ['image/png', '', '23', '[RFC2083]'],
        ['Unassigned', '', '24-39', ''],
        ['application/link-format', '', '40', '[RFC6690]'],
        ['application/xml', '', '41', '[RFC3023]'],
        ['application/octet-stream', '', '42', '[RFC2045][RFC2046]'],
        ['Unassigned', '', '43-46', ''],
        ['application/exi', '', '47', '["Efficient XML Interchange (EXI) Format 1.0 (Second Edition)", February 2014]'],
        ['Unassigned', '', '48-49', ''],
        ['application/json', '', '50', '[RFC8259]'],
        ['application/json-patch+json', '', '51', '[RFC6902]'],
        ['application/merge-patch+json', '', '52', '[RFC7396]'],
        ['Unassigned', '', '53-59', ''],
        ['application/cbor', '', '60', '[RFC8949]'],
        ['application/cwt', '', '61', '[RFC8392]'],
        ['application/multipart-core', '', '62', '[RFC8710]'],
        ['application/cbor-seq', '', '63', '[RFC8742]'],
        ['Unassigned', '', '64-95', ''],
        ['application/cose; cose-type="cose-encrypt"', '', '96', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/cose; cose-type="cose-mac"', '', '97', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/cose; cose-type="cose-sign"', '', '98', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['Unassigned', '', '99-100', ''],
        ['application/cose-key', '', '101', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/cose-key-set', '', '102', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['Unassigned', '', '103-109', ''],
        ['application/senml+json', '', '110', '[RFC8428]'],
        ['application/sensml+json', '', '111', '[RFC8428]'],
        ['application/senml+cbor', '', '112', '[RFC8428]'],
        ['application/sensml+cbor', '', '113', '[RFC8428]'],
        ['application/senml-exi', '', '114', '[RFC8428]'],
        ['application/sensml-exi', '', '115', '[RFC8428]'],
        ['Unassigned', '', '116-139', ''],
        ['application/yang-data+cbor; id=sid', '', '140', '[RFC9254]'],
        ['Unassigned', '', '141-255', ''],
        ['application/coap-group+json', '', '256', '[RFC7390]'],
        ['application/concise-problem-details+cbor', '', '257', '[RFC-ietf-core-problem-details-08]'],
        ['application/swid+cbor', '', '258', '[RFC-ietf-sacm-coswid-22]'],
        ['Unassigned', '', '259-270', ''],
        ['application/dots+cbor', '', '271', '[RFC9132]'],
        ['application/missing-blocks+cbor-seq', '', '272', '[RFC9177]'],
        ['Unassigned', '', '273-279', ''],
        ['application/pkcs7-mime; smime-type=server-generated-key', '', '280', '[RFC7030][RFC8551][RFC9148]'],
        ['application/pkcs7-mime; smime-type=certs-only', '', '281', '[RFC8551][RFC9148]'],
        ['Unassigned', '', '282-283', ''],
        ['application/pkcs8', '', '284', '[RFC5958][RFC8551][RFC9148]'],
        ['application/csrattrs', '', '285', '[RFC7030][RFC9148]'],
        ['application/pkcs10', '', '286', '[RFC5967][RFC8551][RFC9148]'],
        ['application/pkix-cert', '', '287', '[RFC2585][RFC9148]'],
        ['Unassigned', '', '288-289', ''],
        ['application/aif+cbor', '', '290', '[RFC-ietf-ace-aif-07]'],
        ['application/aif+json', '', '291', '[RFC-ietf-ace-aif-07]'],
        ['Unassigned', '', '292-309', ''],
        ['application/senml+xml', '', '310', '[RFC8428]'],
        ['application/sensml+xml', '', '311', '[RFC8428]'],
        ['Unassigned', '', '312-319', ''],
        ['application/senml-etch+json', '', '320', '[RFC8790]'],
        ['Unassigned', '', '321', ''],
        ['application/senml-etch+cbor', '', '322', '[RFC8790]'],
        ['Unassigned', '', '323-339', ''],
        ['application/yang-data+cbor', '', '340', '[RFC9254]'],
        ['application/yang-data+cbor; id=name', '', '341', '[RFC9254]'],
        ['Unassigned', '', '342-431', ''],
        ['application/td+json', '', '432', '["Web of Things (WoT) Thing Description", May 2019]'],
        ['Unassigned', '', '433-835', ''],
        ['application/voucher-cose+cbor (TEMPORARY - registered 2022-04-12, expires 2023-04-12)', '', '836', '[draft-ietf-anima-constrained-voucher-17]'],
        ['Unassigned', '', '837-1541', ''],
        ['Reserved, do not use', '', '1542-1543', '[OMA-TS-LightweightM2M-V1_0]'],
        ['Unassigned', '', '1544-9999', ''],
        ['application/vnd.ocf+cbor', '', '10000', '[Michael_Koster]'],
        ['application/oscore', '', '10001', '[RFC8613]'],
        ['application/javascript', '', '10002', '[RFC4329]'],
        ['Unassigned', '', '10003-11049', ''],
        ['application/json', 'deflate', '11050', '[RFC8259]'],
        ['Unassigned', '', '11051-11059', ''],
        ['application/cbor', 'deflate', '11060', '[RFC8949]'],
        ['Unassigned', '', '11061-11541', ''],
        ['application/vnd.oma.lwm2m+tlv', '', '11542', '[OMA-TS-LightweightM2M-V1_0]'],
        ['application/vnd.oma.lwm2m+json', '', '11543', '[OMA-TS-LightweightM2M-V1_0]'],
        ['application/vnd.oma.lwm2m+cbor', '', '11544', '[OMA-TS-LightweightM2M-V1_2]'],
        ['Unassigned', '', '11545-19999', ''],
        ['text/css', '', '20000', '[RFC2318]'],
        ['Unassigned', '', '20001-29999', ''],
        ['image/svg+xml', '', '30000', '[https://www.w3.org/TR/SVG/mimereg.html]'],
        ['Unassigned', '', '30001-64999', ''],
        ['Reserved for Experimental Use', '', '65000-65535', '[RFC7252]'],
        ]
# fmt: on


def _normalize_media_type(s):
    """Strip out the white space between parameters; doesn't need to fully
    parse the types because it's applied to values of _raw (or to input that'll
    eventually be compared to them and fail)"""
    return s.replace("; ", ";")


class ContentFormatMeta(ExtensibleEnumMeta):
    def __init__(self, name, bases, dict) -> None:
        super().__init__(name, bases, dict)

        # If this were part of the class definition, it would be taken up as an
        # enum instance; hoisting it to the metaclass avoids that special
        # treatment.
        self._by_mt_encoding: Dict[Tuple[str, str], "ContentFormat"] = {}


class ContentFormat(ExtensibleIntEnum, metaclass=ContentFormatMeta):
    """Entry in the `CoAP Content-Formats registry`__ of the IANA Constrained
    RESTful Environments (Core) Parameters group

    .. __: https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats

    Known entries have ``.media_type`` and ``.encoding`` attributes:

    >>> ContentFormat(0).media_type
    'text/plain; charset=utf-8'
    >>> int(ContentFormat.by_media_type('text/plain;charset=utf-8'))
    0
    >>> ContentFormat(60)
    <ContentFormat 60, media_type='application/cbor'>
    >>> ContentFormat(11060).encoding
    'deflate'

    Unknown entries do not have these properties:

    >>> ContentFormat(12345).is_known()
    False
    >>> ContentFormat(12345).media_type                    # doctest: +ELLIPSIS
    Traceback (most recent call last):
        ...
    AttributeError: ...

    Only a few formats are available as attributes for easy access. Their
    selection and naming are arbitrary and biased. The remaining known types
    are available through the :meth:`by_media_type` class method.
    >>> ContentFormat.TEXT
    <ContentFormat 0, media_type='text/plain; charset=utf-8'>

    A convenient property of ContentFormat is that any content format is
    true in a boolean context, and thus when used in alternation with None, can
    be assigned defaults easily:

    >>> requested_by_client = ContentFormat.TEXT
    >>> int(requested_by_client) # Usually, this would always pick the default
    0
    >>> used = requested_by_client or ContentFormat.LINKFORMAT
    >>> assert used == ContentFormat.TEXT
    """

    @classmethod
    def define(cls, number, media_type: str, encoding: str = "identity"):
        s = cls(number)

        if hasattr(s, "media_type"):
            warnings.warn(
                "Redefining media type is a compatibility hazard, but allowed for experimental purposes"
            )

        s._media_type = media_type
        s._encoding = encoding

        cls._by_mt_encoding[(_normalize_media_type(media_type), encoding)] = s

    @classmethod
    def by_media_type(
        cls, media_type: str, encoding: str = "identity"
    ) -> ContentFormat:
        """Produce known entry for a known media type (and encoding, though
        'identity' is default due to its prevalence), or raise KeyError."""
        return cls._by_mt_encoding[(_normalize_media_type(media_type), encoding)]

    def is_known(self):
        return hasattr(self, "media_type")

    @property
    def media_type(self) -> str:
        return self._media_type

    @media_type.setter
    def media_type(self, media_type: str) -> None:
        warnings.warn(
            "Setting media_type or encoding is deprecated, use ContentFormat.define(media_type, encoding) instead.",
            DeprecationWarning,
            stacklevel=1,
        )
        self._media_type = media_type

    @property
    def encoding(self) -> str:
        return self._encoding

    @encoding.setter
    def encoding(self, encoding: str) -> None:
        warnings.warn(
            "Setting media_type or encoding is deprecated, use ContentFormat(number, media_type, encoding) instead.",
            DeprecationWarning,
            stacklevel=1,
        )
        self._encoding = encoding

    @classmethod
    def _rehash(cls):
        """Update the class's cache of known media types

        Run this after having created entries with media type and encoding that
        should be found later on."""
        # showing as a deprecation even though it is a private function because
        # altering media_type/encoding required users to call this.
        warnings.warn(
            "This function is not needed when defining a content type through `.define()` rather than by setting media_type and encoding.",
            DeprecationWarning,
            stacklevel=1,
        )
        cls._by_mt_encoding = {
            (_normalize_media_type(c.media_type), c.encoding): c
            for c in cls._value2member_map_.values()
        }

    def __repr__(self):
        parts = []
        if self.is_known():
            parts.append(f", media_type={self.media_type!r}")
            if self.encoding != "identity":
                parts.append(f", encoding={self.encoding!r}")
        return "<%s %d%s>" % (
            type(self).__name__,
            self,
            "".join(parts),
        )

    def __bool__(self):
        return True

    def _repr_html_(self):
        # The name with title thing isn't too pretty for these ones
        if self.is_known():
            import html

            return f"""<abbr title="Content format {int(self)}{", named ContentFormat." + html.escape(self.name) if hasattr(self, "name") else ""}">{html.escape(self.media_type)}{"@" + self.encoding if self.encoding != "identity" else ""}</abbr>"""
        else:
            return f"""<abbr title="Unknown content format">{int(self)}</abbr>"""

    TEXT = 0
    LINKFORMAT = 40
    OCTETSTREAM = 42
    JSON = 50
    CBOR = 60
    SENML = 112


for _mt, _enc, _i, _source in _raw:
    if _mt in ["Reserved for Experimental Use", "Reserved, do not use", "Unassigned"]:
        continue
    _mt, _, _ = _mt.partition(" (TEMPORARY")
    ContentFormat.define(int(_i), _mt, _enc or "identity")


class _MediaTypes:
    """Wrapper to provide a media_types indexable object as was present up to
    0.4.2"""

    def __getitem__(self, content_format):
        warnings.warn(
            "media_types is deprecated, please use aiocoap.numbers.ContentFormat",
            DeprecationWarning,
            stacklevel=2,
        )
        if content_format is None:
            # That was a convenient idiom to short-circuit through, but would
            # fail through the constructor
            raise KeyError(None)

        cf = ContentFormat(content_format)
        if cf.is_known():
            return _normalize_media_type(cf.media_type)
        else:
            raise KeyError(content_format)

    def get(self, content_format, default=None):
        warnings.warn(
            "media_types is deprecated, please use aiocoap.numbers.ContentFormat",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            return self[content_format]
        except KeyError:
            return default


class _MediaTypesRev:
    """Wrapper to provide a media_types_rev indexable object as was present up
    to 0.4.2"""

    def __getitem__(self, name):
        warnings.warn(
            "media_types_rev is deprecated, please use aiocoap.numbers.ContentFormat",
            DeprecationWarning,
            stacklevel=2,
        )
        if name == "text/plain":
            # deprecated alias. Kept alive for scripts like
            # https://gitlab.f-interop.eu/f-interop-contributors/ioppytest/blob/develop/automation/coap_client_aiocoap/automated_iut.py
            # that run aiocoap-client with text/plain as an argument.
            name = "text/plain;charset=utf-8"
        return int(ContentFormat.by_media_type(name))

    def get(self, name, default=None):
        warnings.warn(
            "media_types_rev is deprecated, please use aiocoap.numbers.ContentFormat",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            return self[name]
        except KeyError:
            return default
