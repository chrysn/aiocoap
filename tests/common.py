# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Non-fixture utilities shared between tests"""

import sys
import os

import aiocoap.defaults

if os.environ.get('AIOCOAP_TESTS_LOOP', None) == 'uvloop':
    import asyncio
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
elif os.environ.get('AIOCOAP_TESTS_LOOP', None) == 'gbulb':
    import gbulb
    gbulb.install()

# All test servers are bound to loopback; if for any reason one'd want to run
# with particular transports, just set them explicitly.
os.environ['AIOCOAP_DTLSSERVER_ENABLED'] = '1'

if 'coverage' in sys.modules:
    PYTHON_PREFIX = [sys.executable, '-m', 'coverage', 'run', '--parallel-mode']
else:
    PYTHON_PREFIX = [sys.executable]

def _find_loopbacknames():
    """Try the lookup results of common 'localhost' names and variations to
    return, in order, a name that resolves to 127.0.0.1, one that resolves to
    ::1 and one that can be resolved to both. If there is no result for any of
    the categories, None is returned in that place."""

    import socket

    candidates = [
            # the obvious choice
            'localhost',
            # seen on debian; ip6-localhost is present on debian too
            'ip6-localhost', 'ip6-loopback'
            ]

    v4 = []
    v6 = []
    for c in candidates:
        try:
            results = socket.getaddrinfo(c, 1234, family=socket.AF_INET)
        except socket.gaierror:
            pass
        else:
            if results and all(x[4] == ('127.0.0.1', 1234) for x in results):
                v4.append(c)
        try:
            # Not probing for AF_INET6 because Windows applies its regular
            # resolution rules (that appear to be "give out V6 addresses to
            # unspecified families only when a V6 route is available") even to
            # 'ip6-loopback' (while 'localhost' is exempt and returns both).
            #
            # If we probed AF_INET6 here, on win32 we'd see ip6-localhost as a
            # usable address, but when the simple6 client transport later asks
            # getaddrinf unspecified (because it's really generic, despite its
            # name), that would come up empty when no route is availasble.
            #
            # (An alternative here would be to query V6 in the first place,
            # check `all` instead of `any` againt com and before appending do
            # another check on whether it still returns something to an
            # unspecified query)
            results = socket.getaddrinfo(c, 1234)
        except socket.gaierror:
            pass
        else:
            if results and any(x[4][:2] == ('::1', 1234) for x in results):
                v6.append(c)

    v4only = [c for c in v4 if c not in v6]
    v6only = [c for c in v6 if c not in v4]
    v46 = [c for c in v4 if c in v6]

    return v4only[0] if v4only else None, \
            v6only[0] if v6only else None, \
            v46[0] if v46 else None

loopbackname_v4, loopbackname_v6, loopbackname_v46 = _find_loopbacknames()

using_simple6 = 'simple6' in list(aiocoap.defaults.get_default_clienttransports())

tcp_disabled = 'tcp' not in os.environ.get('AIOCOAP_SERVER_TRANSPORT', 'tcp is default')
ws_disabled = 'ws' not in os.environ.get('AIOCOAP_SERVER_TRANSPORT', 'ws is default')
dtls_disabled = 'dtls' not in os.environ.get('AIOCOAP_SERVER_TRANSPORT', 'dtls is default')

if __name__ == "__main__":
    print("Python prefix:", PYTHON_PREFIX)
    print("Loopback names:\n  %s (IPv4)\n  %s (IPv6),\n  %s (IPv4+IPv6)"%(loopbackname_v4, loopbackname_v6, loopbackname_v46))
    print("simple6 transport in use:", using_simple6)
    print("TCP disabled:", tcp_disabled)
