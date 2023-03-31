# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tools that I'd like to have in urllib.parse"""

import string

#: "unreserved" characters from RFC3986
unreserved = string.ascii_letters + string.digits + '-._~'

#: "sub-delims" characters from RFC3986
sub_delims = "!$&'()*+,;="

def quote_factory(safe_characters):
    """Return a quote function that escapes all characters not in the
    safe_characters iterable."""
    safe_set = set(ord(x) for x in safe_characters)
    if any(c >= 128 for c in safe_set):
        raise ValueError("quote_factory does not support non-ASCII safe characters")
    def quote(input_string):
        encoded = input_string.encode('utf8')
        return "".join(chr(x) if x in safe_set else "%%%02X" % x for x in encoded)
    return quote
