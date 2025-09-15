#!/bin/sh

set -xeuo pipefail

mv collected-coverage/*/.coverage* .
python3 -m coverage combine
python3 -m coverage report
python3 -m coverage html
mkdir -p public
mv htmlcov public/coverage/
# Link for the wheel goes to the `raw.` URI because that allows CORS,
# making it useful as a pyodide source.
echo '<title>aiocoap build artifacts</title>' > public/index.html
echo '<h1>aiocoap build artifacts</h1><ul>' >> public/index.html
echo '<li><a href="coverage/">Coverage report</a>' >> public/index.html
echo '<li><a href="doc/">Documentation</a>' >> public/index.html
echo '<li><a href="https://raw.codeberg.page/aiocoap/aiocoap/@pages/'$(echo dist/*.whl)'">Current wheel</a>' >> public/index.html
echo '</ul><p>This URL also serves as a Python index API entry point (simple HTML index).' >> public/index.html
echo '<footer>Current version described as '$(git describe --always) >> public/index.html
cat public/index.html
# Our public directory will also serve as PyPI index in application/vnd.pypi.simple.v1+html format
# As this is used without a placeholder, we have to generate a folder for every package:
mkdir public/aiocoap/
echo '<!DOCTYPE html><html><head>' > public/aiocoap/index.html
echo '<meta name="pypi:repository-version" content="1.0"><meta name="pypi:project-status" content="active">' >> public/aiocoap/index.html
echo '<title>Built wheels for aiocoap</title></head>' >> public/aiocoap/index.html
echo '<body><h1>Wheels generated for aiocoap</h1>' >> public/aiocoap/index.html
echo '<a href="../'$(echo dist/*.whl)'">../'$(echo dist/*.whl)'</a>' >> public/aiocoap/index.html
echo '<footer>Current version described as '$(git describe --always) >> public/aiocoap/index.html
echo '</body></html>' >> public/aiocoap/index.html
cat public/aiocoap/index.html
