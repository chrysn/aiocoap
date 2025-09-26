# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""List of values of the Uri-Path-Abbrev option.

This is has no public members while the interface is being explored.
"""

# From draft-ietf-core-uri-path-abbrev-latest, until there's an actually
# established registry.

_map = {
    0: (".well-known", "core"),
    1: (".well-known", "rd"),
    2: (".well-known", "edhoc"),
    301: (".well-known", "est", "crts"),
    302: (".well-known", "est", "sen"),
    303: (".well-known", "est", "sren"),
    304: (".well-known", "est", "skg"),
    305: (".well-known", "est", "skc"),
    306: (".well-known", "est", "att"),
    401: (".well-known", "brski", "es"),
    402: (".well-known", "brski", "rv"),
    403: (".well-known", "brski", "vs"),
}
