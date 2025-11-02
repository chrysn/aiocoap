# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""EDHOC EAD item identifiers

These are provided mainly for internal use, as there is no public API yet to
influence those EDHOC details.
"""

from enum import IntEnum


class EADLabel(IntEnum):
    PADDING = 0

    # CPA suggestion from draft-ietf-ace-edhoc-oscore-profile-09
    SESSION_ID = 5
    REQUEST_CREATION_HINTS = 12
    CRED_BY_VALUE = 15
    ACCESS_TOKEN = 26
