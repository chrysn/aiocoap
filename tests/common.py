# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Non-fixture utilities shared between tests"""

import sys

if 'coverage' in sys.modules:
    PYTHON_PREFIX = [sys.executable, '-m', 'coverage', 'run', '--parallel-mode']
else:
    PYTHON_PREFIX = [sys.executable]
