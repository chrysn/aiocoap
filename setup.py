#!/usr/bin/env python3

# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# txThings is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

from setuptools import setup, find_packages

name = "txThings asyncio branch"
version = "0.0"

setup(
    name=name,
    version=version,
    packages=find_packages(),
    license="MIT",

    author="Maciej Wasilak, Christian Amsüss",
    author_email=", c.amsuess@energyharvesting.at",

    command_options={
        'build_sphinx': {
            'project': ('setup.py', name),
            'version': ('setup.py', version),
            'release': ('setup.py', version),
            }
        }
)
