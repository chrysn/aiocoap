# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import sys
import os

# for aiocoap_index.py
sys.path.insert(0, os.path.abspath("."))
# for aiocoap.meta
sys.path.insert(0, os.path.abspath(".."))

import aiocoap.meta

extensions = [
    "sphinx.ext.autodoc",
    "aiocoap_index",
    "sphinxarg.ext",
]

source_suffix = ".rst"

# This is renamed and already has the default "index" in later Sphinx versions,
# but so far readthedocs renders this with Sphinx 1 (this is more easily
# addressed after an update to use pyproject.toml)
master_doc = "index"

project = "aiocoap"
copyright = "Christian Amsüss and the aiocoap contributors"

# The full version, including alpha/beta/rc tags.
release = aiocoap.meta.version
# The short X.Y version.
version = ".".join(release.split(".")[:2])

html_logo = "logo.svg"
html_favicon = "logo-square.svg"

autodoc_member_order = "bysource"

man_pages = [
    (
        "module/aiocoap.cli.client",
        "aiocoap-client",
        "query CoAP servers from the command line",
        "",
        1,
    ),
    (
        "module/aiocoap.cli.proxy",
        "aiocoap-proxy",
        "forward and reverse proxy server for CoAP",
        "",
        1,
    ),
    ("module/aiocoap.cli.rd", "aiocoap-rd", "Resource Directory server", "", 1),
    (
        "module/aiocoap.cli.fileserver",
        "aiocoap-fileserver",
        "File server for CoAP",
        "",
        1,
    ),
]
