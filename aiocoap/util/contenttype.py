# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Helpers around content types

This uses the terminology clarified in 1_, and primarily deals with content
types in their usual string representation.

Unless content types get used a lot more in aiocoap, this provides only
accessors to some of their relevant properties, without aiming to build
semantically accessible objects to encapsulate them.

.. _1: https://tools.ietf.org/html/draft-bormann-core-media-content-type-format-01"""

def categorize(contenttype: str):
    """Return 'cbor', 'json' or 'link-format' if the content type indicates it
    is that format itself or derived from it."""

    media_type, *_ = contenttype.split(';')
    _, _, subtype = media_type.partition('/')

    if subtype == 'cbor-seq' or subtype.endswith('+cbor-seq'):
        return 'cbor-seq'

    if subtype == 'cbor' or subtype.endswith('+cbor'):
        return 'cbor'

    if subtype == 'json' or subtype.endswith('+json'):
        return 'json'

    if media_type == 'application/link-format':
        return 'link-format'

    return None
