# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Module in which all meaningful numbers are collected. Most of the submodules
correspond to IANA registries."""

from . import constants, types, codes
from .constants import *
from .types import *
from .codes import *
from .optionnumbers import OptionNumber

__all__ = constants.__all__ + types.__all__ + codes.__all__ + ['OptionNumber']

media_types = {0: 'text/plain;charset=utf-8',
               16: 'application/cose;cose-type="cose-encrypt0"',
               17: 'application/cose;cose-type="cose-mac0"',
               18: 'application/cose;cose-type="cose-sign1"',
               40: 'application/link-format',
               41: 'application/xml',
               42: 'application/octet-stream',
               47: 'application/exi',
               50: 'application/json',
               51: 'application/json-patch+json',
               52: 'application/merge-patch+json',
               60: 'application/cbor',
               61: 'application/cwt',
               62: 'application/multipast-core', # draft-ietf-core-multipart-ct
               64: 'application/link-format+cbor', # draft-ietf-core-links-json-10
               70: 'application/oscon', # draft-ietf-core-object-security-01
               96: 'application/cose;cose-type="cose-encrypt"',
               97: 'application/cose;cose-type="cose-mac"',
               98: 'application/cose;cose-type="cose-sign"',
               101: 'application/cose-key',
               102: 'application/cose-key-set',
               110: 'application/senml+json',
               111: 'application/sensml+json',
               112: 'application/senml+cbor',
               113: 'application/sensml+cbor',
               114: 'application/senml-exi',
               115: 'application/sensml-exi',
               256: 'application/coap-group+json',
               280: 'application/pkcs7-mime;smime-type=server-generated-key',
               281: 'application/pkcs7-mime;smime-type=certs-only',
               282: 'application/pkcs7-mime;smime-type=CMC-Request',
               283: 'application/pkcs7-mime;smime-type=CMC-Response',
               284: 'application/pkcs8',
               285: 'application/csrattrs',
               286: 'application/pkcs10',
               310: 'application/senml+xml',
               311: 'application/sensml+xml',
               1000: 'application/vnd.ocf+cbor',
               11542: 'application/vnd.oma.lwm2m+tlv',
               11543: 'application/vnd.oma.lwm2m+json',
               504: 'application/link-format+json', # draft-ietf-core-links-json-10
               }
"""A map from CoAP-assigned integral codes to Internet media type descriptions."""

media_types_rev = {v:k for k, v in media_types.items()}
# deprecated alias. Kept alive for scripts like
# https://gitlab.f-interop.eu/f-interop-contributors/ioppytest/blob/develop/automation/coap_client_aiocoap/automated_iut.py
# that run aiocoap-client with text/plain as an argument.
#
# FIXME: Make access to this raise a DeprecationWarning
media_types_rev['text/plain'] = media_types_rev['text/plain;charset=utf-8']
