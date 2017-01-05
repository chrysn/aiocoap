# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""This is a subset of what the Python 3.6 secrets module gives, for
compatibility with earlier Python versions and for as long as there is no
published & widespread backported version of it"""

try:
    from secrets import token_bytes
except ImportError:
    # from pep506
    import os

    def token_bytes(nbytes):
        return os.urandom(nbytes)
