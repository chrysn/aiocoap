#!/usr/bin/env python3
# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

from pathlib import Path
import shutil
import urllib.request

out = Path(__file__).parent / "for-launcher"
out.mkdir(exist_ok=True)
contrib = Path(__file__).parent.parent

with (out / "android.txt").open("w") as androidtxt:
    androidtxt.write("title=aiocoap kivy widget\n")
    androidtxt.write("author=chrysn\n")
    androidtxt.write("orientation=portrait\n")

shutil.copytree(contrib / "widgets_common", out / "widgets_common", dirs_exist_ok=True)
shutil.copytree(contrib.parent / "aiocoap", out / "aiocoap", dirs_exist_ok=True)

wheels = [
    "https://files.pythonhosted.org/packages/d5/e1/af78b099196feaab7c0252108abc4f5cfd36d255ac47c4b4a695ff838bf9/cbor2-5.4.6-py3-none-any.whl",
    "https://files.pythonhosted.org/packages/93/69/e391bd51bc08ed9141ecd899a0ddb61ab6465309f1eb470905c0c8868081/docutils-0.19-py3-none-any.whl",
]

wheelfilenames = []

for w in wheels:
    with urllib.request.urlopen(w) as request:
        wheelname = w[w.rindex("/") + 1 :]
        with (out / wheelname).open("wb") as wheel_out:
            wheel_out.write(request.read())
        wheelfilenames.append(wheelname)

with (out / "main.py").open("w") as mainpy:
    mainpy.write("import sys\n")
    mainpy.write("from pathlib import Path\n")
    mainpy.write("_here = Path(__file__).parent\n")
    for w in wheelfilenames:
        mainpy.write(f"sys.path.append(str(_here / '{w}') + '/')\n")
    with (contrib / "aiocoap-kivy-widget").open() as infile:
        mainpy.write(infile.read())
