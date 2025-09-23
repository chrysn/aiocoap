# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Module in which all meaningful numbers are collected. Most of the submodules
correspond to IANA registries.

The contents of the :mod:`.constants`, :mod:`.types` and :mod:`.codes` modules
are accessible through this module directly; :mod:`.contentformat`'s and
:mod:`.optionnumbers`' sole :class:`.contentformat.ContentFormat` and
:class:`.optionnumbers.OptionNumber` classes are accessible in the same way.
"""

import warnings
import string

from . import constants, types, codes
from .contentformat import ContentFormat, _MediaTypes, _MediaTypesRev
from .optionnumbers import OptionNumber

# These lists are hard-coded in because static checkers need them explicit. The code below helps keep it up to date.
# fmt: off
from .constants import COAPS_PORT, COAP_PORT, MAX_REGULAR_BLOCK_SIZE_EXP, MCAST_ALL, MCAST_IPV4_ALLCOAPNODES, MCAST_IPV6_LINKLOCAL_ALLCOAPNODES, MCAST_IPV6_LINKLOCAL_ALLNODES, MCAST_IPV6_SITELOCAL_ALLCOAPNODES, MCAST_IPV6_SITELOCAL_ALLNODES, Reliable, SHUTDOWN_TIMEOUT, TransportTuning, Unreliable
from .types import Type, CON, NON, ACK, RST
from .codes import Code, EMPTY, GET, POST, PUT, DELETE, FETCH, PATCH, iPATCH, CREATED, DELETED, VALID, CHANGED, CONTENT, CONTINUE, BAD_REQUEST, UNAUTHORIZED, BAD_OPTION, FORBIDDEN, NOT_FOUND, METHOD_NOT_ALLOWED, NOT_ACCEPTABLE, REQUEST_ENTITY_INCOMPLETE, CONFLICT, PRECONDITION_FAILED, REQUEST_ENTITY_TOO_LARGE, UNSUPPORTED_CONTENT_FORMAT, UNPROCESSABLE_ENTITY, TOO_MANY_REQUESTS, INTERNAL_SERVER_ERROR, NOT_IMPLEMENTED, BAD_GATEWAY, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT, PROXYING_NOT_SUPPORTED, HOP_LIMIT_REACHED, CSM, PING, PONG, RELEASE, ABORT
__all__ = ['COAPS_PORT', 'COAP_PORT', 'MAX_REGULAR_BLOCK_SIZE_EXP', 'MCAST_ALL', 'MCAST_IPV4_ALLCOAPNODES', 'MCAST_IPV6_LINKLOCAL_ALLCOAPNODES', 'MCAST_IPV6_LINKLOCAL_ALLNODES', 'MCAST_IPV6_SITELOCAL_ALLCOAPNODES', 'MCAST_IPV6_SITELOCAL_ALLNODES', 'Reliable', 'SHUTDOWN_TIMEOUT', 'TransportTuning', 'Unreliable', 'Type', 'CON', 'NON', 'ACK', 'RST', 'Code', 'EMPTY', 'GET', 'POST', 'PUT', 'DELETE', 'FETCH', 'PATCH', 'iPATCH', 'CREATED', 'DELETED', 'VALID', 'CHANGED', 'CONTENT', 'CONTINUE', 'BAD_REQUEST', 'UNAUTHORIZED', 'BAD_OPTION', 'FORBIDDEN', 'NOT_FOUND', 'METHOD_NOT_ALLOWED', 'NOT_ACCEPTABLE', 'REQUEST_ENTITY_INCOMPLETE', 'CONFLICT', 'PRECONDITION_FAILED', 'REQUEST_ENTITY_TOO_LARGE', 'UNSUPPORTED_CONTENT_FORMAT', 'UNPROCESSABLE_ENTITY', 'TOO_MANY_REQUESTS', 'INTERNAL_SERVER_ERROR', 'NOT_IMPLEMENTED', 'BAD_GATEWAY', 'SERVICE_UNAVAILABLE', 'GATEWAY_TIMEOUT', 'PROXYING_NOT_SUPPORTED', 'HOP_LIMIT_REACHED', 'CSM', 'PING', 'PONG', 'RELEASE', 'ABORT', 'OptionNumber', 'ContentFormat']
# fmt: on

if __debug__:
    _generated_all = (
        constants.__all__
        + types.__all__
        + codes.__all__
        + ["OptionNumber", "ContentFormat"]
    )
    if _generated_all != __all__:
        warnings.warn(f"""Hardcoded __all__ is out of sync (as are imports, probably), please updated to

        from .constants import {", ".join(constants.__all__)}
        from .types import {", ".join(types.__all__)}
        from .codes import {", ".join(codes.__all__)}
        __all__ = {_generated_all}""")

media_types = _MediaTypes()
media_types_rev = _MediaTypesRev()


def __getattr__(name):
    if name[0] in string.ascii_uppercase and hasattr(
        constants._default_transport_tuning, name
    ):
        warnings.warn(
            f"{name} is deprecated, use through the message's transport_tuning instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return getattr(constants._default_transport_tuning, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")
