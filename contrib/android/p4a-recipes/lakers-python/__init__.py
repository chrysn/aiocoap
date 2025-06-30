# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from pythonforandroid.recipe import RustCompiledComponentsRecipe


class LakersRecipe(RustCompiledComponentsRecipe):
    name = "lakers-python"
    version = "0.5.0"
    url = "https://files.pythonhosted.org/packages/7e/06/49defc46cb7cffd46daf06538bbd4f6dcf4da511036fbb73ea856a02def4/lakers_python-0.5.0.tar.gz"
    sha512sum = "7f11d99ba8781b9bcd30154ec08143994c6f71d69bf2d8b7ac88dea1a62db952d348828893dc79415b3913c04cda8e08f2828b7cc6538fb83f28366847a21ee0"
    depends = []


recipe = LakersRecipe()
