# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import doctest
import aiocoap.defaults
import os

def load_tests(loader, tests, ignore):
    for root, dn, fn in os.walk('aiocoap'):
        for f in fn:
            if not f.endswith('.py'):
                continue
            p = os.path.join(root, f)
            if 'oscore' in p and aiocoap.defaults.oscore_missing_modules():
                continue
            if 'resourcedirectory' in p or 'fileserver' in p or p in ('aiocoap/cli/rd.py', 'aiocoap/util/linkformat.py') and aiocoap.defaults.linkheader_missing_modules():
                continue
            if p in ('aiocoap/util/prettyprint.py', 'aiocoap/util/linkformat_pygments.py') and aiocoap.defaults.prettyprint_missing_modules():
                continue
            tests.addTests(doctest.DocTestSuite(p[:-3].replace('/', '.')))
    return tests
