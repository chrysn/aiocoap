#!/usr/bin/env python3
# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import sys
import shutil
from pathlib import Path
import subprocess

import venv

out = Path(__file__).parent / "for-buildozer"
out.mkdir(exist_ok=True)

buildozer_venv = Path(__file__).parent / "venv-buildozer"

contrib = Path(__file__).parent.parent

with (out / "buildozer.spec").open("w") as buildozerspec:
    buildozerspec.write("""\
[app]
title = aiocoap widget demo
package.name = aiocoap_widget_demo
package.domain = org.example
source.dir = .
source.include_exts = py
version = 0.1

# docutils for kivy rst widget
#
# everything after that is aiocoap[prettyprint,oscore,ws] spelled out (without
# aiocoap as that's copied in below). for some reason, ge25519's dependency on
# fe25519 needs to be spelled out.
requirements = python3,kivy,docutils,termcolor,cbor2,pygments,cbor-diag,cryptography,filelock,ge25519,fe25519,websockets
orientation = portrait

fullscreen = 0
android.permissions = INTERNET

# You may need to adjust this to your device
android.arch = armeabi-v7a
""")

shutil.copy(contrib / "aiocoap-kivy-widget", out / "main.py")
# We could use aiocoap from PyPI, but so far things only work with this
# branch's version.
shutil.copytree(contrib / "widgets_common", out / "widgets_common", dirs_exist_ok=True)
shutil.copytree(contrib.parent / "aiocoap", out / "aiocoap", dirs_exist_ok=True)

venv.create(buildozer_venv, with_pip=True)
subprocess.check_call(
    [
        "bash",
        "-e",
        "-c",
        """\
        source ../venv-buildozer/bin/activate
        pip install cython buildozer
        buildozer $@
""",
        "buildozer",
    ]
    + sys.argv[1:],
    cwd=out,
)
