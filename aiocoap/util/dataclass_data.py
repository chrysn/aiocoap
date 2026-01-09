# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tools to load a typed dataclass from CBOR/JSON/TOML/YAML-model data.

Unlike what is in the aiocoap.credentials module, this works from the fixed
assumption that the item is a dataclass (as opposed to having an arbitrary
constructor), which should ease things.

**Caveats**:

* The module expects the data classes' annotations to be types and
  not strings, and therefore can't be used with types defined under `from
  __future__ import annotations`.

* While ``Optional[str]`` and other primitives are supported, child load-store
  classes need to be dressed as ``| None`` (i.e., a ``Union``). This can be
  simplified when support for Python 3.13 is dropped, as both versions
  have the type ``typing.Union`` starting with Python 3.14.

>>> from dataclasses import dataclass
>>> from typing import Optional
>>> @dataclass
... class Inner(LoadStoreClass):
...     some_text: str
...     some_number: Optional[int]
>>> @dataclass
... class Top(LoadStoreClass):
...     x: str
...     y: Inner | None
>>> Top.load({"x": "test", "y": {"some-text": "one", "some-number": 42}})
Top(x='test', y=Inner(some_text='one', some_number=42))
"""

import dataclasses
import types
from typing import Self


class LoadStoreClass:
    @classmethod
    def load(cls, data: dict, prefix: str = "", depth_limit: int = 16) -> Self:
        """Creates an instance from the given data dictionary.

        Keys are used to populate fields like in the initializer; dashes ("-")
        in names are replaced with underscores ("_") so that Python-idiomatic
        field names (in snake_case) can be used with TOML idiomatic item names
        (in kebab-case).

        Values are type-checked against the annotations, and unknown fields are
        disallowed. When annotations indicate another ``LoadStoreClass``,
        initialization recurses into that type up to a depth limit.

        The ``prefix`` is used for error messages: It builds up in the recursive
        build process and thus gives the user concrete guidance as to where in
        the top-level item the trouble was. For data loaded from files, it is
        prudent to give the file name in this argument.

        This reliably raises ``ValueError`` or its subtypes on unacceptable
        data as long as the class is set up in a supported way.
        """

        assert dataclasses.is_dataclass(cls)

        prefix = f"{prefix}/" if prefix else prefix

        fields = {f.name: f for f in dataclasses.fields(cls)}

        kwargs = {}

        for key, value in data.items():
            keyprefix = f"{prefix}{key}"
            f = key.replace("-", "_")
            fieldtype = fields[f].type
            if isinstance(value, fieldtype):
                pass
            elif (
                # The simple case: It *is* that type.
                isinstance(fieldtype, type)
                and issubclass(load_as := fieldtype, LoadStoreClass)
            ) or (
                # The complex case: It is a union, and we can find out which
                # one is the one we can use; stored in load_as right away.
                #
                # When Python 3.13 support is dropped, types.UnionType can
                # become types.Union, and we'll gain support for Optioinal too
                isinstance(fieldtype, types.UnionType)
                and len(
                    [
                        load_as := x
                        for x in fieldtype.__args__
                        if issubclass(x, LoadStoreClass)
                    ]
                )
                == 1
            ):
                # The isinstance check is needed for issubclass to work in the
                # first place; FIXME: rather than assuming it's the top-level
                # item, get a list of candidate LoadStoreClass subclasses, so
                # that we can also process Optional[Foo] or even Foo | Bar.

                # FIXME: allow annotating single distinct non-dict-value, eg.
                # like Cargo.toml's implicit version in dependencies. (Right
                # now we can do this can be done at the parent level, maybe
                # that suffices?).
                if not isinstance(value, dict):
                    raise ValueError(
                        f"Type mismatch on {keyprefix}: Expected dictionary to populate {load_as.__name__} with, found {type(value).__name__}"
                    )
                if depth_limit == 0:
                    raise ValueError("Nesting exceeded limit in {keyprefix}")
                value = load_as.load(
                    value, prefix=keyprefix, depth_limit=depth_limit - 1
                )
            else:
                # FIXME:
                # - For lists and dicts, evaluate items (can be deferred until we actually have any)
                # - Special treatment for bytes: Accept {"acii": "hello"} and {"hex": "001122"}
                # - Special treatment for Path (probably with new filename argument)
                # - In union handling, support multiple, possibly fanning out by disambiguator keys?

                # For regular types "__name__ works, but unions and similar don't have one
                fieldtypename = getattr(fieldtype, "__name__", str(fieldtype))
                raise ValueError(
                    f"Type mismatch on {keyprefix}: Expected {fieldtypename}, found {type(value).__name__}"
                )
            kwargs[f] = value

        try:
            return cls(**kwargs)
        except TypeError as e:
            missing = [
                f.name
                for f in dataclasses.fields(cls)
                if f.name not in kwargs and f.default is dataclasses.MISSING
            ]
            if missing:
                # The likely case -- what else might go wrong?
                raise ValueError(
                    f"Construcintg an instance of {cls.__name__} at {prefix}, these items are missing: {', '.join(m.replace('_', '-') for m in missing)}"
                )
            else:
                raise ValueError(
                    f"Constructing instance of {cls.__name__} at {keyprefix} failed for unexpected reasons"
                ) from e
