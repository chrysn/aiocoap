#!/bin/sh
# SPDX-FileCopyrightText: Christian Amsüss
# SPDX-License-Identifier: MIT

set -xeuo pipefail

mkdir -p public

# always the case in CI … but not locally, and not when we do quick CI runs
# where tests are skipped
if [ -e .coverage ]
then
    export COVERAGE_FILE=.coverage/cov
    python3 -m coverage combine
    python3 -m coverage report
    python3 -m coverage html -d public/coverage/
fi

./.woodpecker/badges.sh

WHEEL=$(cd dist && echo *.whl)
DESCRIBE=$(git describe --always)
cat > public/index.html <<EOF
<!DOCTYPE html>
<html>
    <head>
        <title>aiocoap build artifacts</title>
    </head>
    <body>
        <h1>aiocoap build artifacts</h1>
        <p>This page lists automatically generated output of the latest unreleased version of aiocoap.
        See <a href="https://codeberg.org/aiocoap/aiocoap">the canonical git repository</a> for sources and general information about the project.

        <ul>
            <li><a href="coverage/">Coverage report</a>
            <li><a href="doc/">Documentation</a> (locally built; official and versioned <a href="https://aiocoap.readthedocs.io/en/latest/">at readthedocs.io</a>)
            <li><a href="./dist/${WHEEL}">Current wheel</a>
        </ul>

        <p>Released versions of aiocoap are published at the <a href="https://pypi.org/project/aiocoap/">the Python package index (PyPI)</a>.
        <p>This URL (but without the trailing slash) serves as a Python index API entry point (simple HTML index) for the latest unreleased version.
        <p>You can install aiocoap from here using:
        <p><code>$ pip install --extra-index-url https://aiocoap.codeberg.page/aiocoap 'aiocoap[all]'</code>
        <p>or in Pyodide (for which this index also contains some additional binary dependencies in the right versions):
        <p><code>&gt;&gt;&gt; await micropip.install("aiocoap[all]", index_urls=["https://aiocoap.codeberg.page/aiocoap", "PYPI"])</code>

        <footer>Current version described as <tt>${DESCRIBE}</tt>
    </body>
</html>
EOF
cat public/index.html

# Our files accumulate, so let's keep the older versions we do have visible also in the index.
# At least in CI, we'll have to get that list before we can access it.
git fetch origin pages --depth=1 --filter=blob:none

# Debug helpers for when something goes awry in the index building
ls -la public/dist
git ls-tree --name-only origin/pages:dist/

# We're mainly hosting aiocoap wheels here, but have some lakers-python builds
# in the pages tree as well to aid use from pyodide before pyodide-recipes have
# been disseminated all through the ecosystem.
#
# Note that for actual use by pyodide, the resulting pages are currently
# mirrored onto coap.amsuess.com to get CORS and media types right … and all
# that is a workaround for <https://codeberg.org/forgejo/forgejo/issues/9361>
# -- once that's through, we can just push packages, remove these from pages
# (possibly truncating its history to get it slim again) and switch over to
# Codeberg packages completely.
for PACKAGE in aiocoap lakers-python
do
    # Our public directory will also serve as PyPI index in application/vnd.pypi.simple.v1+html format.
    # The base URI is the pages URI without a trailing slash.

    PACKAGEFILE=$(echo $PACKAGE | tr - _)
    mkdir -p public/$PACKAGE/
    cat > public/$PACKAGE/index.html <<EOF
<!DOCTYPE html>
<html>
    <head>
        <meta name="pypi:repository-version" content="1.0">
        <meta name="pypi:project-status" content="active">
        <title>Package files for ${PACKAGE}</title>
    </head>
    <body>
        <h1>Package files for ${PACKAGE}</h1>
        <ul>
EOF
    for WHEEL in $( ( git ls-tree --name-only origin/pages:dist/ ; cd public/dist/ && ls ) |grep "^${PACKAGEFILE}" | sort -u )
    do
        cat >> public/$PACKAGE/index.html <<EOF
<li><a href="../dist/${WHEEL}">${WHEEL}</a>
EOF
    done
    cat >> public/$PACKAGE/index.html <<EOF
        </ul>
        <footer>Current version described as <tt>${DESCRIBE}</tt>
    </body>
</html>
EOF
    cat public/$PACKAGE/index.html
done
