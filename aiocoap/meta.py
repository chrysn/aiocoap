# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

#: Make library version internally
#:
#: This is not supposed to be used in any decision-making process (use package
#: dependencies for that) or workarounds, but used by command-line tools or the
#: impl-info link to provide debugging information.
version = "0.4.3.post0"

#: URI used to describe the current version of the library
#:
#: This is used the same way as `version` but when a URI is required, for
#: example as a default value for .well-known/core's rel=impl-info link.
library_uri = "https://christian.amsuess.com/tools/aiocoap/#version-" + version
