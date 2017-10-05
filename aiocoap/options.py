# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from itertools import chain
import struct

from .numbers import *

def _read_extended_field_value(value, rawdata):
    """Used to decode large values of option delta and option length
       from raw binary form."""
    if value >= 0 and value < 13:
        return (value, rawdata)
    elif value == 13:
        return (rawdata[0] + 13, rawdata[1:])
    elif value == 14:
        return (struct.unpack('!H', rawdata[:2])[0] + 269, rawdata[2:])
    else:
        raise ValueError("Value out of range.")


def _write_extended_field_value(value):
    """Used to encode large values of option delta and option length
       into raw binary form.
       In CoAP option delta and length can be represented by a variable
       number of bytes depending on the value."""
    if value >= 0 and value < 13:
        return (value, b'')
    elif value >= 13 and value < 269:
        return (13, struct.pack('!B', value - 13))
    elif value >= 269 and value < 65804:
        return (14, struct.pack('!H', value - 269))
    else:
        raise ValueError("Value out of range.")


def _single_value_view(option_number, doc=None):
    """Generate a property for a given option number, where the option is not
    repeatable. For getting, it will return the value of the first option
    object with matching number. For setting, it will remove all options with
    that number and create one with the given value. The property can be
    deleted, resulting in removal of the option from the header.

    For consistency, setting the value to None also clears the option. (Note
    that with the currently implemented optiontypes, None is not a valid value
    for any of them)."""

    def _getter(self, option_number=option_number):
        options = self.get_option(option_number)
        if not options:
            return None
        else:
            return options[0].value

    def _setter(self, value, option_number=option_number):
        self.delete_option(option_number)
        if value is not None:
            self.add_option(option_number.create_option(value=value))

    def _deleter(self, option_number=option_number):
        self.delete_option(option_number)

    return property(_getter, _setter, _deleter, doc or "Single-value view on the %s option."%option_number)

def _items_view(option_number, doc=None):
    """Generate a property for a given option number, where the option is
    repeatable. For getting, it will return a tuple of the values of the option
    objects with matching number. For setting, it will remove all options with
    that number and create new ones from the given iterable."""

    def _getter(self, option_number=option_number):
        return tuple(o.value for o in self.get_option(option_number))

    def _setter(self, value, option_number=option_number):
        self.delete_option(option_number)
        for v in value:
            self.add_option(option_number.create_option(value=v))

    def _deleter(self, option_number=option_number):
        self.delete_option(option_number)

    return property(_getter, _setter, _deleter, doc=doc or "Iterable view on the %s option."%option_number)

def _empty_presence_view(option_number, doc=None):
    """Generate a property for a given option number, where the option is not
    repeatable and (usually) empty. The values True and False are mapped to
    presence and absence of the option."""

    def _getter(self, option_number=option_number):
        return bool(self.get_option(option_number))

    def _setter(self, value, option_number=option_number):
        self.delete_option(option_number)
        if value:
            self.add_option(option_number.create_option())

    return property(_getter, _setter, doc=doc or "Presence of the %s option."%option_number)

class Options(object):
    """Represent CoAP Header Options."""

    # this is not so much an optimization as a safeguard -- if custom
    # attributes were placed here, they could be accessed but would not be
    # serialized
    __slots__ = ["_options"]

    def __init__(self):
        self._options = {}

    def __eq__(self, other):
        if not isinstance(other, Options):
            return NotImplemented
        # this implementation is much easier than implementing equality on
        # StringOption etc
        return self.encode() == other.encode()

    def __repr__(self):
        text = ", ".join("%s: %s"%(OptionNumber(k), " / ".join(map(str, v))) for (k, v) in self._options.items())
        return "<aiocoap.options.Options at %#x: %s>"%(id(self), text or "empty")

    def decode(self, rawdata):
        """Passed a CoAP message body after the token as rawdata, fill self
        with the options starting at the beginning of rawdata, an return the
        rest of the message (the body)."""
        option_number = OptionNumber(0)

        while len(rawdata) > 0:
            if rawdata[0] == 0xFF:
                return rawdata[1:]
            dllen = rawdata[0]
            delta = (dllen & 0xF0) >> 4
            length = (dllen & 0x0F)
            rawdata = rawdata[1:]
            (delta, rawdata) = _read_extended_field_value(delta, rawdata)
            (length, rawdata) = _read_extended_field_value(length, rawdata)
            option_number += delta
            option = option_number.create_option(decode=rawdata[:length])
            self.add_option(option)
            rawdata = rawdata[length:]
        return b''

    def encode(self):
        """Encode all options in option header into string of bytes."""
        data = []
        current_opt_num = 0
        option_list = self.option_list()
        for option in option_list:
            delta, extended_delta = _write_extended_field_value(option.number - current_opt_num)
            length, extended_length = _write_extended_field_value(option.length)
            data.append(bytes([((delta & 0x0F) << 4) + (length & 0x0F)]))
            data.append(extended_delta)
            data.append(extended_length)
            data.append(option.encode())
            current_opt_num = option.number
        return (b''.join(data))

    def add_option(self, option):
        """Add option into option header."""
        self._options.setdefault(option.number, []).append(option)

    def delete_option(self, number):
        """Delete option from option header."""
        if number in self._options:
            self._options.pop(number)

    def get_option(self, number):
        """Get option with specified number."""
        return self._options.get(number, ())

    def option_list(self):
        return chain.from_iterable(sorted(self._options.values(), key=lambda x: x[0].number))

    uri_path = _items_view(OptionNumber.URI_PATH)
    uri_query = _items_view(OptionNumber.URI_QUERY)
    location_path = _items_view(OptionNumber.LOCATION_PATH)
    location_query = _items_view(OptionNumber.LOCATION_QUERY)
    block2 = _single_value_view(OptionNumber.BLOCK2)
    block1 = _single_value_view(OptionNumber.BLOCK1)
    content_format = _single_value_view(OptionNumber.CONTENT_FORMAT)
    etag = _single_value_view(OptionNumber.ETAG, "Single ETag as used in responses")
    etags = _items_view(OptionNumber.ETAG, "List of ETags as used in requests")
    if_none_match = _empty_presence_view(OptionNumber.IF_NONE_MATCH)
    observe = _single_value_view(OptionNumber.OBSERVE)
    accept = _single_value_view(OptionNumber.ACCEPT)
    uri_host = _single_value_view(OptionNumber.URI_HOST)
    uri_port = _single_value_view(OptionNumber.URI_PORT)
    proxy_uri = _single_value_view(OptionNumber.PROXY_URI)
    proxy_scheme = _single_value_view(OptionNumber.PROXY_SCHEME)
    size1 = _single_value_view(OptionNumber.SIZE1)
    object_security = _single_value_view(OptionNumber.OBJECT_SECURITY)
    max_age = _single_value_view(OptionNumber.MAX_AGE)
    if_match = _items_view(OptionNumber.IF_MATCH)
    no_response = _single_value_view(OptionNumber.NO_RESPONSE)
