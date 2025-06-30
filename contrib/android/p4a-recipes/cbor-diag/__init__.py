# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from pythonforandroid.recipe import RustCompiledComponentsRecipe


class CborDiagRecipe(RustCompiledComponentsRecipe):
    name = "cbor-diag"
    version = "1.1.0"
    url = "https://files.pythonhosted.org/packages/db/f6/9921162053f195eaa7e22cae9172e0d3bdda62282d76480163d1de872f35/cbor_diag-1.1.0.tar.gz"
    sha512sum = "d53a706237e2b2dd1e6c4afb712543c4feab1b69bfb3faa2ad39cd5cbba44106f815eba911764e3d076c91fffb1845e99b1a591dc29c96bc4fca389e731b5433"
    depends = []


recipe = CborDiagRecipe()
