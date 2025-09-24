#!/bin/sh
# SPDX-FileCopyrightText: Christian Amsüss
# SPDX-License-Identifier: MIT

set -xeuo pipefail

export COVERAGE_FILE=.coverage/cov

python3 -m coverage xml -o - | genbadge coverage -i - -o public/badges/coverage.svg
