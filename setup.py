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

name = "aiocoap"
version = "0.3"
description = "Python CoAP library"
longdescription = __doc__

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
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],

    python_requires='>=3.3',
    extras_require={
        'linkheader': ['LinkHeader'],
        ':python_version<"3.4"': ['asyncio'],
        },

    entry_points={
        'console_scripts': [
            'aiocoap-client = aiocoap.cli.client:sync_main',
            'aiocoap-proxy = aiocoap.cli.proxy:sync_main',
            ]
        },

    command_options={
        'build_sphinx': {
            'project': ('setup.py', name),
            'version': ('setup.py', version),
            'release': ('setup.py', version),
            }
        },

    cmdclass={
        'cite': Cite,
        },

    test_suite='tests',
)
