#!/usr/bin/env python3

# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""aiocoap is a Python library for writing servers and clients for the CoAP
(Constrained Application) Protocol, which is used mainly in the context of IoT
(Internet of Things) devices."""

from setuptools import setup, Command

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

for k, v in extras_require.items():
    if k.startswith(':') or k == 'all' or k == 'docs':
        continue

    # Most extras are required for docs to build. TinyDTLS is an exception
    # because no module imports it at module level. (This is convenient also
    # because TinyDTLS installation fails on readthedocs for unknown reasons.)
    if k != 'tinydtls':
        extras_require['docs'].extend(v)

    extras_require['all'].extend(v)

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
    extras_require=extras_require,

    cmdclass={
        'cite': Cite,
        },

    # not strictly required any more since tests are now runnable as `-m
    # unittest`, but results in more concise output
    test_suite='tests',
)
