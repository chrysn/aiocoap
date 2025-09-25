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
# Link for the wheel goes to the `raw.` URI because that allows CORS,
# making it useful as a pyodide source.
cat > public/index.html <<EOF
<!DOCTYPE html>
<html>
    <head>
        <title>aiocoap build artifacts</title>
    </head>
    <body>
        <h1>aiocoap build artifacts</h1>
        <ul>
            <li><a href="coverage/">Coverage report</a>
            <li><a href="doc/">Documentation</a>
            <li><a href="https://raw.codeberg.page/aiocoap/aiocoap/@pages/dist/${WHEEL}">Current wheel</a>
        </ul>
<!--
        <p>This URL (but without the trailing slash) also serves as a Python index API entry point (simple HTML index).

        Or "could serve", because in pyodide practice it works neither with the
        aiocoap.codeberg.page version (for lack of CORS), nor with the
        raw.codeberg.page version (for lack of non-text/plain content types,
        and micropip relies on content types)
-->
        <footer>Current version described as ${DESCRIBE}
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
        <footer>Current version described as ${DESCRIBE}
    </body>
</html>
EOF
    cat public/$PACKAGE/index.html
done
