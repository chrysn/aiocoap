# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Container module for transports

Transports are expected to be the modular backends of aiocoap, and implement
the specifics of eg. TCP, WebSockets or SMS, possibly divided by backend
implementations as well. (If, for example, a non-posix platform is added, it
might be easier to rewrite the :mod:`.udp6` for that platform
instead of "ifdef hell").
"""
