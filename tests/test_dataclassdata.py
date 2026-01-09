# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import unittest
from dataclasses import dataclass

from aiocoap.util.dataclass_data import LoadStoreClass


@dataclass
class Inner2(LoadStoreClass):
    b: str
    a: int = 1


@dataclass
class Inner1(LoadStoreClass):
    x: Inner2
    y: Inner2
    z: float


@dataclass
class Outer(LoadStoreClass):
    label: str
    inner: Inner1


class TestDataclassData(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(
            Outer.load(
                {
                    "label": "hello",
                    "inner": {
                        "x": {"b": "x"},
                        "y": {"a": 2, "b": "X"},
                        "z": 1.5,
                    },
                }
            ),
            Outer(
                label="hello",
                inner=Inner1(x=Inner2(a=1, b="x"), y=Inner2(a=2, b="X"), z=1.5),
            ),
        )

    def test_type(self):
        try:
            Outer.load(
                {
                    "label": "hello",
                    "inner": {
                        "x": {"b": "x"},
                        "y": {"a": 2, "b": 42},
                        "z": 1.5,
                    },
                }
            )
        except ValueError as e:
            if "inner/y/b" in str(e) and "Expected str, found int" in str(e):
                pass
            else:
                raise Exception("Path to missing field was not shown") from e
        else:
            raise Exception("Incomplete data was loaded")

    def test_missing(self):
        try:
            Outer.load(
                {
                    "label": "hello",
                    "inner": {
                        "x": {"b": "x"},
                        "y": {"a": 2},  # no "b"
                        "z": 1.5,
                    },
                }
            )
        except ValueError as e:
            if "inner/y" in str(e) and "missing: b":
                pass
            else:
                raise Exception("Path to missing field was not shown") from e
        else:
            raise Exception("Incomplete data was loaded")
