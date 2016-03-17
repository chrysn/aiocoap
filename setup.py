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

name = "aiocoap"
version = "0.2"
description = "Python CoAP library"
longdescription = __doc__

setup(
    name=name,
    version=version,
    description=description,
    packages=find_packages(),

    author="Maciej Wasilak, Christian Amsüss",
    author_email="Christian Amsüss <c.amsuess@energyharvesting.at>",
    url="https://github.com/chrysn/aiocoap",

    keywords=['coap', 'asyncio', 'iot'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
        ],

    extras_require={
        'linkheader': ['LinkHeader'],
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

    test_suite='tests',
)
