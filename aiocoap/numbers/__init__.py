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
# flake8 doesn't see through the global re-export
from .constants import * # noqa: F401 F403
from .types import * # noqa: F401 F403
from .codes import * # noqa: F401 F403
from .contentformat import ContentFormat, _MediaTypes, _MediaTypesRev
from .optionnumbers import OptionNumber

__all__ = constants.__all__ + types.__all__ + codes.__all__ + ['OptionNumber', 'ContentFormat']

media_types = _MediaTypes()
media_types_rev = _MediaTypesRev()

def __getattr__(name):
    if name[0] in string.ascii_uppercase and hasattr(constants._default_transport_tuning, name):
        warnings.warn(f"{name} is deprecated, use through the message's transport_tuning instead", DeprecationWarning, stacklevel=2)
        return getattr(constants._default_transport_tuning, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")
