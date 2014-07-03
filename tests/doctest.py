# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import unittest
import doctest
import aiocoap
import glob

def load_tests(loader, tests, ignore):
    for p in glob.glob("aiocoap/**/*.py"):
        if "queuewithend" in p:
            # exclude queuewithend module, it's unstable yet anyway
            continue
        tests.addTests(doctest.DocTestSuite(p[:-3].replace('/', '.')))
    return tests
