# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This module contains in-place modifications to the LinkHeader module to
satisfy RFC6690 constraints.

It is a general nursery for what aiocoap needs of link-format management before
any of this is split out into its own package.
"""

import link_header

_CBOR_ENCODING = {
        'href': 1,
        'rel': 2,
        'anchor': 3,
        'rev': 4,
        'hreflang': 5,
        'media': 6,
        'title': 7,
        'type': 8,
        'rt': 9,
        'if': 10,
        'sz': 11,
        'ct': 12,
        'obs': 13,
        }
_CBOR_DECODING = {v: k for (k, v) in _CBOR_ENCODING.items()}

class LinkFormat(link_header.LinkHeader):
    def __str__(self):
        return ','.join(str(link) for link in self.links)

    def as_cbor_bytes(self):
        import cbor2 as cbor

        return cbor.dumps([l.as_cbor_data() for l in self.links])

    def as_json_string(self):
        import json

        return json.dumps([l.as_json_data() for l in self.links])

    @classmethod
    def from_json_string(cls, encoded):
        import json

        try:
            array = json.loads(encoded)
        except json.JSONDecodeError:
            raise link_header.ParseException("Not valid JSON")
        if not isinstance(array, list):
            raise link_header.ParseException("Not a JSON array")
        return cls(Link.from_json_data(x) for x in array)

    @classmethod
    def from_cbor_bytes(cls, encoded):
        import cbor2 as cbor

        try:
            # FIXME: don't silently accept trailing bytes
            array = cbor.loads(encoded)
        except: # FIXME in library: give one subclassable "failure to decode" error
            raise link_header.ParseException("Not valid CBOR")
        if not isinstance(array, list):
            raise link_header.ParseException("Not a CBOR array")
        return cls(Link.from_cbor_data(x) for x in array)

class Link(link_header.Link):
    # This is copy-pasted from the link_header module's code, just replacing
    # the '; ' with ';'.
    #
    # Original copyright Michael Burrows <mjb@asplake.co.uk>, distributed under
    # the BSD license
    def __str__(self):
        def str_pair(key, value):
            if value is None:
                return key
# workaround to accomodate copper
#            elif RE_ONLY_TOKEN.match(value) or key.endswith('*'):
#                return '%s=%s' % (key, value)
            else:
                return '%s="%s"' % (key, value.replace('"', r'\"'))
        return ';'.join(['<%s>' % self.href] +
                         [str_pair(key, value)
                          for key, value in self.attr_pairs])

    def as_json_data(self):
        entry = {}
        entry['href'] = self.href
        for k, v in self.attr_pairs:
            entry.setdefault(k, []).append(True if v is None else v)
        entry = {k: v[0] if len(v) == 1 else v for (k, v) in entry.items()}
        return entry

    def as_cbor_data(self):
        return {_CBOR_ENCODING.get(k, k): v
                for (k, v) in self.as_json_data().items()}

    @classmethod
    def from_json_data(cls, obj):
        if not isinstance(obj, dict):
            raise link_header.ParseException("Entry is not a dict")

        href = obj.get('href')
        if not isinstance(href, str):
            raise link_header.ParseException("href is not a single string")
        link = Link(href)
        for k, values in obj.items():
            if not isinstance(values, list):
                values = (values,)
            for v in values:
                if isinstance(v, str):
                    link.attr_pairs.append((k, v))
                elif v is True:
                    link.attr_pairs.append((k, None))
                elif isinstance(v, dict):
                    raise link_header.ParseException("Language tags not supported by link_header")
                else:
                    raise link_header.ParseException("Unsupported value type")
        return link

    @classmethod
    def from_cbor_data(cls, obj):
        if not isinstance(obj, dict):
            raise link_header.ParseException("Entry is not a dict")

        if any(k in _CBOR_ENCODING for k in obj):
            # it says "MUST NOT accept"
            raise link_header.ParseException("Unencoded attribute")

        return cls.from_json_data(
                {_CBOR_DECODING.get(k, k): v for (k, v) in obj.items()})

def parse(linkformat):
    data = link_header.parse(linkformat)
    data.__class__ = LinkFormat
    for l in data.links:
        l.__class__ = Link
    return data
