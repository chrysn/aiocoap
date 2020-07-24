# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

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

    if subtype == 'cbor' or subtype.endswith('+cbor'):
        return 'cbor'

    if subtype == 'json' or subtype.endswith('+json'):
        return 'json'

    if media_type == 'application/link-format':
        return 'link-format'

    return None
