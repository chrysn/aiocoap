#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from setuptools import setup, Command


class Cite(Command):
    description = """Print how to cite aiocoap in a publication"""

    user_options = [("bibtex", None, "Output citation data as bibtex")]
    boolean_options = ["bibtex"]

    def initialize_options(self):
        self.bibtex = False

    def finalize_options(self):
        pass

    def run(self):
        if self.bibtex:
            print(self.bibtex_text)
        else:
            print(self.plain_text)

    plain_text = """Amsüss, Christian and the aiocoap contributors. aiocoap: Python CoAP Library. 2013–. https://christian.amsuess.com/tools/aiocoap/"""

    bibtex_text = """@Misc{,
        author = {Christian Amsüss and aiocoap contributors},
        title = {{aiocoap}: Python CoAP Library},
        year = {2013--},
        url = {https://christian.amsuess.com/tools/aiocoap/},
        }"""


setup(
    cmdclass={
        "cite": Cite,
    },
)
