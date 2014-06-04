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
        # currently does not do the apidoc automatic stuff; run `python3.4 =sphinx-apidoc -f -e -o doc iot` to add the .rst files but don't check them in
        'build_sphinx': {
            'project': ('setup.py', name),
            'version': ('setup.py', version),
            'release': ('setup.py', version),
            }
        }
)
