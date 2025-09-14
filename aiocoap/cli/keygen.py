# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""A tool for creating key pairs for use in credentials

Note that this tool operates on secrets stored in unencrypted files, protectd
by restrictively set file system permissions. While this is common practice
with many tools in the UNIX world, it might be surprising to users coming from
multi-factor environments."""

import aiocoap.meta
import aiocoap.defaults

import argparse
from pathlib import Path


def build_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--version", action="version", version="%(prog)s " + aiocoap.meta.version
    )

    subparsers = p.add_subparsers(required=True, dest="subcommand")
    generate = subparsers.add_parser(
        "generate",
        help="This generates an"
        " EDHOC key, stores it in a key file that is only readable by the"
        " user, and prints the corresponding public key information in a way"
        " suitable for inclusion in credentials maps.",
    )
    generate.add_argument("keyfile", help="File to store the secret key in", type=Path)
    generate.add_argument(
        "--kid", help="Hexadecimal key identifier", type=bytes.fromhex
    )
    generate.add_argument("--subject", help="Text placed in the CCS", type=str)

    return p


def main():
    p = build_parser()

    args = p.parse_args()

    missmods = aiocoap.defaults.oscore_missing_modules()
    if missmods:
        p.error(
            f'Dependencies missing, consider installing aiocoap as "aiocoap[oscore]" or "aiocoap[all]". Missing modules: {", ".join(missmods)}'
        )

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
