# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Module in which all meaningful numbers are collected. Most of the submodules
correspond to IANA registries.

The contents of the :mod:`.constants`, :mod:`.types` and :mod:`.codes` modules
are accessible through this module directly; :mod:`.contentformat`'s and
:mod:`.optionnumbers`' sole :class:`.contentformat.ContentFormat` and
:class:`.optionnumbers.OptionNumber` classes are accessible in the same way.
"""

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
