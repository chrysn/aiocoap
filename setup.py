#!/usr/bin/env python3

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
