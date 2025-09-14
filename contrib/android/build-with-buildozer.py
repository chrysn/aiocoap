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

subprocess.check_call(
    [
        "inkscape",
        "../../doc/logo-square.svg",
        "-o",
        out / "square.png",
        "--export-width=512",
    ]
)

with (out / "buildozer.spec").open("w") as buildozerspec:
    buildozerspec.write("""\
[app]
title = aiocoap widget demo
package.name = aiocoap_widget_demo
package.domain = org.example
source.dir = .
source.include_exts = py
version = 0.1
presplash.filename = square.png
icon.filename = square.png

# docutils for kivy rst widget
#
# everything after that is aiocoap[prettyprint,oscore,ws] spelled out (without
# aiocoap as that's copied in below). for some reason, ge25519's dependency on
# fe25519 needs to be spelled out. (Likewise for cryptography and cffi?)
requirements = python3,kivy,docutils,cbor2,pygments,cbor-diag,colorlog,cryptography,cffi,filelock,ge25519,fe25519,lakers-python,websockets
# ... of which some need local recipes, otherwise p4a will just spick the amd64
# wheels into the apk:
p4a.local_recipes = ../p4a-recipes
orientation = portrait

fullscreen = 0
android.permissions = INTERNET

# You may need to adjust this to your device
android.archs = armeabi-v7a, arm64-v8a

# A consequence of using the main branch buildozer / see
# https://github.com/kivy/buildozer/issues/1699 workaround below.
p4a.branch = develop
""")

shutil.copy(contrib / "aiocoap-kivy-widget", out / "main.py")
# We could use aiocoap from PyPI, but so far things only work with this
# branch's version.
shutil.copytree(contrib / "widgets_common", out / "widgets_common", dirs_exist_ok=True)
shutil.copytree(contrib.parent / "aiocoap", out / "aiocoap", dirs_exist_ok=True)

venv.create(buildozer_venv, with_pip=True)
# Note that we need the full "activate" dance for buildozer as it will want to
# run more --user installs and access to cython in the PATH, and that only
# works with fully set-up activation and not simply by running
# venv/bin/buildozer.
subprocess.check_call(
    [
        "bash",
        "-e",
        "-c",
        """\
        source ../venv-buildozer/bin/activate
        # Workaround-For: https://github.com/kivy/buildozer/issues/1699 until next release
        pip install cython git+https://github.com/kivy/buildozer
        buildozer $@
""",
        "buildozer",
    ]
    + sys.argv[1:],
    cwd=out,
)
