#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""aiocoap is a Python library for writing servers and clients for the CoAP
(Constrained Application) Protocol, which is used mainly in the context of IoT
(Internet of Things) devices."""

from setuptools import setup, find_packages, Command
import os
import os.path

version = "0.4.7.post0" # Don't forget meta.version and doc/conf.py

# When introducing something new, make sure to update doc/installation.rst
extras_require = {
        # Extra is still present for compatibility, but its dependency has been vendored in.
        'linkheader': [],
        # ge25519 is a workaround for
        # <https://github.com/pyca/cryptography/issues/5557>; being pure python
        # it's light enough to not warrant a dedicated group-oscore extra.
        'oscore': ['cbor2', 'cryptography (>= 2.0)', 'filelock', 'ge25519'],
        'tinydtls': ['DTLSSocket >= 0.1.11a1'],
        'ws': ['websockets'],
        'prettyprint': ['termcolor', 'cbor2', 'pygments', 'cbor-diag'],
        'docs': ['sphinx', 'sphinx-argparse'], # extended below
        'all': [], # populated below, contains everything but documentation dependencies for easier installation
        }
tests_require = [] # populated below

test_extras = extras_require.keys()
if 'AIOCOAP_TEST_EXTRAS' in os.environ:
    test_extras = os.environ['AIOCOAP_TEST_EXTRAS'].split(':')

for k, v in extras_require.items():
    if k.startswith(':') or k == 'all' or k == 'docs':
        continue

    # Most extras are required for docs to build. TinyDTLS is an exception
    # because no module imports it at module level. (This is convenient also
    # because TinyDTLS installation fails on readthedocs for unknown reasons.)
    if k != 'tinydtls':
        extras_require['docs'].extend(v)

    extras_require['all'].extend(v)
    if k in test_extras:
        tests_require.extend(v)

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
    # Once out of beta (ie. when the pesky warnings are gone), we could do
    #
    # [tool.setuptools.dynamic]
    # version = { attr = "aiocoap.meta.version" }
    #
    # in pyproject.toml instead
    version=version,
    # Likewise, this could be done with [tool.setuptools.packages.find]
    packages=find_packages(exclude=["tests"]),

    extras_require=extras_require,
    tests_require=tests_require,

    # see doc/README.doc seciton "dependency hack"
    install_requires=extras_require['docs'] if 'READTHEDOCS' in os.environ else [],

    cmdclass={
        'cite': Cite,
        },

    # not strictly required any more since tests are now runnable as `-m
    # unittest`, but results in more concise output
    test_suite='tests',
)
