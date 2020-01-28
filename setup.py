#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""aiocoap is a Python library for writing servers and clients for the CoAP
(Constrained Application) Protocol, which is used mainly in the context of IoT
(Internet of Things) devices."""

from setuptools import setup, find_packages
from distutils.core import Command
import os

name = "aiocoap"
version = "0.4b2" # Don't forget meta.version and doc/conf.py
description = "Python CoAP library"
longdescription = __doc__

# When introducing something new, make sure to update doc/installation.rst
extras_require = {
        'linkheader': ['LinkHeader'],
        'oscore': ['hkdf', 'cbor', 'cryptography (>= 2.0)', 'filelock'],
        'tinydtls': ['DTLSSocket >= 0.1.11a1'],
        'prettyprint': ['termcolor', 'cbor', 'LinkHeader', 'pygments'],
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

    plain_text = """Amsüss, Christian and Wasilak, Maciej. aiocoap: Python CoAP Library. Energy Harvesting Solutions, 2013–. http://github.com/chrysn/aiocoap/"""

    bibtex_text = """@Misc{,
        author = {Christian Amsüss and Maciej Wasilak},
        organization = {Energy Harvesting Solutions},
        title = {{aiocoap}: Python CoAP Library},
        year = {2013--},
        url = {http://github.com/chrysn/aiocoap/},
        }"""

setup(
    name=name,
    version=version,
    description=description,
    packages=find_packages(),

    author="Maciej Wasilak, Christian Amsüss",
    author_email="c.amsuess@energyharvesting.at",
    url="https://github.com/chrysn/aiocoap",

    keywords=['coap', 'asyncio', 'iot'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: AsyncIO',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],

    python_requires='>=3.5',
    extras_require=extras_require,
    tests_require=tests_require,

    # see doc/README.doc seciton "dependency hack"
    install_requires=extras_require['docs'] if 'READTHEDOCS' in os.environ else [],

    entry_points={
        'console_scripts': [
            'aiocoap-client = aiocoap.cli.client:sync_main',
            'aiocoap-proxy = aiocoap.cli.proxy:sync_main',
            'aiocoap-rd = aiocoap.cli.rd:sync_main [linkheader]',
            # link header is no important dependency (only used for RD
            # registration), but currently a hard one
            'aiocoap-fileserver = aiocoap.cli.fileserver:FileServerProgram.sync_main [linkheader]',
            ]
        },

    cmdclass={
        'cite': Cite,
        },

    # not strictly required any more since tests are now runnable as `-m
    # unittest`, but results in more concise output
    test_suite='tests',
)
