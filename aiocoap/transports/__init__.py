# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Container module for transports

Transports are expected to be the modular backends of aiocoap, and implement
the specifics of eg. TCP, WebSockets or SMS, possibly divided by backend
implementations as well.

Transports are not part of the API, so the class descriptions in the modules
are purely informational.

Multiple transports can be used in parallel in a single :class:`.Context`, and
are loaded in a particular sequence. Some transports will grab all addresses of
a given protocol, so they might not be practical to combine. Which transports
are started in a given Context follows the
:func:`.defaults.get_default_clienttransports` function.

The available transports are:

.. the files in this directory.
"""
