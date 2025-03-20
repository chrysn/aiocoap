# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import doctest
import aiocoap.defaults
import os
import sys
from pathlib import Path


def _load_tests():
    """This is an adapted load_test of the old unittest mechanism, adapted
    crudely to work with pytest. It can most probably be done better, eg. by
    producing a list of doctest-able files for use with doctest-glob (which
    would allow getting actual breakpoints where things fail, or other pytest
    niceties), but as it is, it at least covers the cases again."""
    i = 0
    base = Path(aiocoap.__file__).parent
    # FIXME: Once Python 3.11 support is dropped, revert the commit that added
    # this line and check whether any module dependencies can be removed.
    for root, dn, fn in os.walk(base):
        for f in fn:
            if not f.endswith(".py"):
                continue
            parts = list(Path(root).relative_to(base.parent).parts)
            if f != "__init__.py":
                parts.append(Path(f).stem)
            p = ".".join(parts)
            if (
                "oscore" in p or "edhoc" in p
            ) and aiocoap.defaults.oscore_missing_modules():
                continue
            if (
                "cryptography_additions" in p
                and aiocoap.defaults.oscore_missing_modules()
            ):
                continue
            if p.endswith(".ws") and aiocoap.defaults.ws_missing_modules():
                continue
            if (
                "resourcedirectory" in p
                or "fileserver" in p
                or p in ("aiocoap.cli.rd", "aiocoap.util.linkformat")
                and aiocoap.defaults.linkheader_missing_modules()
            ):
                continue
            if (
                p in ("aiocoap.util.prettyprint", "aiocoap.util.linkformat_pygments")
                and aiocoap.defaults.prettyprint_missing_modules()
            ):
                continue
            if (
                p in ("aiocoap.util.pyodide_websockets",)
                and not aiocoap.defaults.is_pyodide
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

                globals()["test_%03d" % i] = test


_load_tests()
