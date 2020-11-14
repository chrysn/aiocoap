# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import unittest
import aiocoap.defaults

oscore_modules = aiocoap.defaults.oscore_missing_modules()
_skip_unless_oscore = unittest.skipIf(oscore_modules, "Modules missing for running OSCORE tests: %s" % (oscore_modules,))

@_skip_unless_oscore
class UtilCryptographyAdditions(unittest.TestCase):
    def test(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from aiocoap.util.cryptography_additions import sk_to_curve25519, pk_to_curve25519

        # From https://github.com/ace-wg/Hackathon-109/blob/master/GroupKeys.md and
        # https://github.com/ace-wg/Hackathon-109/blob/master/GroupDerivation.md,
        # private1 is Rikard Test 2 Entity 1, private2 is Rikard Test 2 Entity 2
        private1 = bytes.fromhex('397CEB5A8D21D74A9258C20C33FC45AB152B02CF479B2E3081285F77454CF347')
        private2 = bytes.fromhex('70559B9EECDC578D5FC2CA37F9969630029F1592AFF3306392AB15546C6A184A')
        shared_reference = bytes.fromhex('4546babdb9482396c167af11d21953bfa49eb9f630c45de93ee4d3b9ef059576')

        private1 = ed25519.Ed25519PrivateKey.from_private_bytes(private1)
        private2 = ed25519.Ed25519PrivateKey.from_private_bytes(private2)

        private1_x = sk_to_curve25519(private1)
        private2_x = sk_to_curve25519(private2)

        assert private1_x.exchange(private2_x.public_key()) == \
                private2_x.exchange(private1_x.public_key()) == \
                shared_reference

        public2 = private2.public_key()
        public2_x = pk_to_curve25519(public2)

        assert private1_x.exchange(public2_x) == shared_reference
