#!/bin/sh
# SPDX-FileCopyrightText: Christian Amsüss
# SPDX-License-Identifier: MIT

set -xeuo pipefail

mkdir -p public

# always the case in CI … but not locally, and not when we do quick CI runs
# where tests are skipped
if [ -e collected-coverage ]
then
    mv collected-coverage/*/.coverage* .
    python3 -m coverage combine
    python3 -m coverage report
    python3 -m coverage html
    mv htmlcov public/coverage/
fi

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
# Our public directory will also serve as PyPI index in application/vnd.pypi.simple.v1+html format
# As this is used without a placeholder, we have to generate a folder for every package:
mkdir -p public/aiocoap/
cat > public/aiocoap/index.html <<EOF
<!DOCTYPE html>
<html>
    <head>
        <meta name="pypi:repository-version" content="1.0">
        <meta name="pypi:project-status" content="active">
        <title>Built wheels for aiocoap</title>
    </head>
    <body>
        <h1>Wheels generated for aiocoap</h1>
        <a href="../dist/${WHEEL}">${WHEEL}</a>
        <footer>Current version described as ${DESCRIBE}
    </body>
</html>
EOF
cat public/aiocoap/index.html
