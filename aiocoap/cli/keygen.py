# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""aiocoap-keygen is a tool for creating key pairs for use in credentials"""

import aiocoap.meta
import aiocoap.defaults

import argparse
from pathlib import Path

def main():
    p = argparse.ArgumentParser(description=__doc__, epilog="Please beware that ")
    p.add_argument('--version', action="version", version='%(prog)s ' + aiocoap.meta.version)

    subparsers = p.add_subparsers(required=True, dest="subcommand")
    generate = subparsers.add_parser("generate", help="""This generates an
        EDHOC key, stores it in a key file that is only readable by the user,
        and prints the corresponding public key information in a way suitable
        for inclusion in credentials maps.""")
    generate.add_argument('keyfile', help="File to store the secret key in", type=Path)
    generate.add_argument('--kid', help="Hexadecimal key identifier", type=bytes.fromhex)
    generate.add_argument('--subject', help="Text placed in the CCS", type=str)

    args = p.parse_args()

    missmods = aiocoap.defaults.oscore_missing_modules()
    if missmods:
        p.error(f"Dependencies missing, consider installing aiocoap as \"aiocoap[oscore]\" or \"aiocoap[all]\". Missing modules: {', '.join(missmods)}")

    from aiocoap import edhoc
    import cbor2
    import cbor_diag

    if args.subcommand == "generate":
        try:
            key = edhoc.CoseKeyForEdhoc.generate(args.keyfile)
        except FileExistsError:
            raise p.error("Output file already exists")

        public = key.as_ccs(args.kid, args.subject)
        print(cbor_diag.cbor2diag(cbor2.dumps(public, canonical=True), pretty=False))
    else:
        raise RuntimeError(f"Unimplemented subcommand {args.subcommand=}")

if __name__ == "__main__":
    main()
