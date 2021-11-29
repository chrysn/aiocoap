# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Module containing the CoRE parameters / CoAP Content-Formats registry"""

from __future__ import annotations

from ..util import ExtensibleIntEnum
import warnings

# _raw can be updated from: `curl https://www.iana.org/assignments/core-parameters/content-formats.csv | python3 -c 'import csv, sys; print(list(csv.reader(sys.stdin))[1:])'`

_raw = [
        ['text/plain; charset=utf-8', '', '0', '[RFC2046][RFC3676][RFC5147]'],
        ['Unassigned', '', '1-15', ''],
        ['application/cose; cose-type="cose-encrypt0"', '', '16', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/cose; cose-type="cose-mac0"', '', '17', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/cose; cose-type="cose-sign1"', '', '18', '[RFC-ietf-cose-rfc8152bis-struct-15]'],
        ['application/ace+cbor', '', '19', '[RFC-ietf-ace-oauth-authz-45]'],
        ['Unassigned', '', '20', ''],
        ['image/gif', '', '21', '[https://www.w3.org/Graphics/GIF/spec-gif89a.txt]'],
        ['image/jpeg', '', '22', '[ISO/IEC 10918]'],
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
        ['Unassigned', '', '116-255', ''],
        ['application/coap-group+json', '', '256', '[RFC7390]'],
        ['Unassigned', '', '257-270', ''],
        ['application/dots+cbor', '', '271', '[RFC9132]'],
        ['application/missing-blocks+cbor-seq', '', '272', '[RFC-ietf-core-new-block-14]'],
        ['Unassigned', '', '273-279', ''],
        ['application/pkcs7-mime; smime-type=server-generated-key', '', '280', '[RFC7030][RFC8551][RFC-ietf-ace-coap-est-18]'],
        ['application/pkcs7-mime; smime-type=certs-only', '', '281', '[RFC8551][RFC-ietf-ace-coap-est-18]'],
        ['Unassigned', '', '282-283', ''],
        ['application/pkcs8', '', '284', '[RFC5958][RFC8551][RFC-ietf-ace-coap-est-18]'],
        ['application/csrattrs', '', '285', '[RFC7030][RFC-ietf-ace-coap-est-18]'],
        ['application/pkcs10', '', '286', '[RFC5967][RFC8551][RFC-ietf-ace-coap-est-18]'],
        ['application/pkix-cert', '', '287', '[RFC2585][RFC-ietf-ace-coap-est-18]'],
        ['Unassigned', '', '288-309', ''],
        ['application/senml+xml', '', '310', '[RFC8428]'],
        ['application/sensml+xml', '', '311', '[RFC8428]'],
        ['Unassigned', '', '312-319', ''],
        ['application/senml-etch+json', '', '320', '[RFC8790]'],
        ['Unassigned', '', '321', ''],
        ['application/senml-etch+cbor', '', '322', '[RFC8790]'],
        ['Unassigned', '', '323-431', ''],
        ['application/td+json', '', '432', '["Web of Things (WoT) Thing Description", May 2019]'],
        ['Unassigned', '', '433-1541', ''],
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

def _normalize_media_type(s):
    """Strip out the white space between parameters; doesn't need to fully
    parse the types because it's applied to values of _raw (or to input that'll
    eventually be compared to them and fail)"""
    return s.replace('; ', ';')

class ContentFormat(ExtensibleIntEnum):
    """Entry in the `CoAP Content-Formats registry`__ of the IANA Constrained
    RESTful Environments (Core) Parameters group

    .. __: https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats

    Known entries have ``.media_type`` and ``.encoding`` attributes:

    >>> ContentFormat(0).media_type
    'text/plain; charset=utf-8'
    >>> int(ContentFormat.by_media_type('text/plain;charset=utf-8'))
    0
    >>> ContentFormat(60)
    <ContentFormat 60, media_type='application/cbor', encoding='identity'>
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
    <ContentFormat 0, media_type='text/plain; charset=utf-8', encoding='identity'>

    A convenient property of ContentFormat is that any known content format is
    true in a boolean context, and thus when used in alternation with None, can
    be assigned defaults easily:

    >>> requested_by_client = ContentFormat.TEXT
    >>> int(requested_by_client) # Usually, this would always pick the default
    0
    >>> used = requested_by_client or ContentFormat.LINKFORMAT
    >>> assert used == ContentFormat.TEXT
    """

    @classmethod
    def by_media_type(cls, media_type: str, encoding: str = 'identity') -> ContentFormat:
        """Produce known entry for a known media type (and encoding, though
        'identity' is default due to its prevalence), or raise KeyError."""
        return cls._by_mt_encoding[(_normalize_media_type(media_type), encoding)]

    def is_known(self):
        return hasattr(self, "media_type")

    @classmethod
    def _rehash(cls):
        """Update the class's cache of known media types

        Run this after having created entries with media type and encoding that
        should be found later on."""
        cls._by_mt_encoding = {(_normalize_media_type(c.media_type), c.encoding): c for c in cls._value2member_map_.values()}

    def __repr__(self):
        return "<%s %d%s>" % (type(self).__name__, self, ', media_type=%r, encoding=%r' % (self.media_type, self.encoding) if self.is_known() else "")

    def __bool__(self):
        return True

    TEXT = 0
    LINKFORMAT = 40
    OCTETSTREAM = 42
    JSON = 50
    CBOR = 60
    SENML = 112

for (_mt, _enc, _i, _source) in _raw:
    if _mt in ["Reserved for Experimental Use", "Reserved, do not use", "Unassigned"]:
        continue
    _cf = ContentFormat(int(_i))
    _cf.media_type = _mt
    _cf.encoding = _enc or "identity"
ContentFormat._rehash()


class _MediaTypes:
    """Wrapper to provide a media_types indexable object as was present up to
    0.4.2"""
    def __getitem__(self, content_format):
        warnings.warn("media_types is deprecated, please use aiocoap.numbers.ContentFormat", DeprecationWarning, stacklevel=2)
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
        warnings.warn("media_types is deprecated, please use aiocoap.numbers.ContentFormat", DeprecationWarning, stacklevel=2)
        try:
            return self[content_format]
        except KeyError:
            return default

class _MediaTypesRev:
    """Wrapper to provide a media_types_rev indexable object as was present up
    to 0.4.2"""
    def __getitem__(self, name):
        warnings.warn("media_types_rev is deprecated, please use aiocoap.numbers.ContentFormat", DeprecationWarning, stacklevel=2)
        if name == 'text/plain':
            # deprecated alias. Kept alive for scripts like
            # https://gitlab.f-interop.eu/f-interop-contributors/ioppytest/blob/develop/automation/coap_client_aiocoap/automated_iut.py
            # that run aiocoap-client with text/plain as an argument.
            name = 'text/plain;charset=utf-8'
        return int(ContentFormat.by_media_type(name))

    def get(self, name, default=None):
        warnings.warn("media_types_rev is deprecated, please use aiocoap.numbers.ContentFormat", DeprecationWarning, stacklevel=2)
        try:
            return self[name]
        except KeyError:
            return default
