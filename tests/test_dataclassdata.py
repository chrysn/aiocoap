# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from aiocoap.util.dataclass_data import LoadStoreClass


@dataclass
class Inner2(LoadStoreClass):
    b: str
    a: int = 1


@dataclass
class Inner1(LoadStoreClass):
    x: Inner2
    z: float
    y: Inner2 | str | None = None


@dataclass
class Outer(LoadStoreClass):
    inner: Inner1
    label: Optional[str] = None
    items2: str | dict[str, Inner2] = "default"


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
                    "items2": "hello",
                }
            ),
            Outer(
                label="hello",
                inner=Inner1(x=Inner2(a=1, b="x"), y=Inner2(a=2, b="X"), z=1.5),
                items2="hello",
            ),
        )

    def test_valid_and_optional_not_used(self):
        self.assertEqual(
            Outer.load(
                {
                    "inner": {
                        "x": {"b": "x"},
                        "z": 1.5,
                    },
                }
            ),
            Outer(
                inner=Inner1(x=Inner2(a=1, b="x"), z=1.5),
            ),
        )

    def test_valid_and_alternative_type(self):
        self.assertEqual(
            Outer.load(
                {
                    "inner": {
                        "x": {"b": "x"},
                        "y": "hi",
                        "z": 1.5,
                    },
                    "items2": {"a": {"b": "2a"}},
                }
            ),
            Outer(
                inner=Inner1(x=Inner2(a=1, b="x"), y="hi", z=1.5),
                items2={"a": Inner2(b="2a")},
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
            if "inner/y" in str(e) and "missing: b" in str(e):
                pass
            else:
                raise Exception("Path to missing field was not shown") from e
        else:
            raise Exception("Incomplete data was loaded")

    def test_unknown_item(self):
        try:
            Outer.load(
                {
                    "inner": {
                        "y": {"b": "y", "unknown": 42},  # "unknown" is not recognized
                        "z": 1.5,
                    },
                }
            )
        except ValueError as e:
            if "inner/y" in str(e) and "Item 'unknown' not recognized" in str(e):
                pass
            else:
                raise Exception("Extra element was not pointed to") from e
        else:
            raise Exception("Incomplete data was loaded")

    def test_unsupported_alternative(self):
        try:
            Outer.load(
                {
                    "inner": {
                        "x": {"b": "x"},
                        "z": 1.5,
                        "y": 1.1,  # should be string or dict
                    },
                }
            )
        except ValueError as e:
            # or something to that effect
            if (
                "inner/y" in str(e)
                and "Expected dict (representing Inner2) or str or NoneType, found float"
                in str(e)
            ):
                pass
            else:
                raise Exception("Type error did not point to legal options") from e
        else:
            raise Exception("Erroneous data was loaded")

    def test_path(self):
        @dataclass
        class HasPath(LoadStoreClass):
            p: Path

        self.assertEqual(
            HasPath.load({"p": "../up.file"}, basefile=Path("config.d/test.json")).p,
            # Must not be shortened: config.d might be a symlink.
            Path("config.d/../up.file"),
        )
        self.assertEqual(
            HasPath.load(
                {"p": "/absolute.file"}, basefile=Path("config.d/test.json")
            ).p,
            Path("/absolute.file"),
        )
        self.assertEqual(
            HasPath.load(
                {"p": "local.file"},
            ).p,
            Path("local.file"),
        )
