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
import sys

def _load_tests():
    """This is an adapted load_test of the old unittest mechanism, adapted
    crudely to work with pytest. It can most probably be done better, eg. by
    producing a list of doctest-able files for use with doctest-glob (which
    would allow getting actual breakpoints where things fail, or other pytest
    niceties), but as it is, it at least covers the cases again."""
    i = 0
    for root, dn, fn in os.walk('aiocoap'):
        for f in fn:
            if not f.endswith('.py'):
                continue
            p = os.path.join(root, f)
            p = p[:-3].replace(os.sep, '.')
            if 'oscore' in p and aiocoap.defaults.oscore_missing_modules():
                continue
            if 'cryptography_additions' in p and aiocoap.defaults.oscore_missing_modules():
                continue
            if p.endswith('.ws') and aiocoap.defaults.ws_missing_modules():
                continue
            if 'resourcedirectory' in p or 'fileserver' in p or p in ('aiocoap.cli.rd', 'aiocoap.util.linkformat') and aiocoap.defaults.linkheader_missing_modules():
                continue
            if p in ('aiocoap.util.prettyprint', 'aiocoap.util.linkformat_pygments') and aiocoap.defaults.prettyprint_missing_modules():
                continue
            if 'udp6' in p and (
                    # due to https://foss.heptapod.net/pypy/pypy/issues/3249
                    'PyPy' in sys.version
                    # if_indextoname etc introduced only in 3.8
                    or (sys.platform == 'win32' and sys.version_info < (3, 8))
                    ):
                continue
            for t in doctest.DocTestSuite(p):
                i += 1
                def test(t=t):
                    result = t.run()
                    for f in result.failures:
                        print(f[1])
                        raise RuntimeError("Doctest failed (see above)")
                    for e in result.errors:
                        raise e
                globals()['test_%03d' % i] = test

_load_tests()
