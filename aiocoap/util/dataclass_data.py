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

>>> from dataclasses import dataclass
>>> from typing import Optional
>>> @dataclass
... class Inner(LoadStoreClass):
...     some_text: str
...     some_number: Optional[int]
>>> @dataclass
... class Top(LoadStoreClass):
...     x: str | bytes
...     y: Optional[Inner]
>>> Top.load({"x": "test", "y": {"some-text": "one", "some-number": 42}})
Top(x='test', y=Inner(some_text='one', some_number=42))
"""

import dataclasses
from typing import Self, Union
import sys


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
            try:
                fieldtype = fields[f].type
            except KeyError:
                raise ValueError(
                    f"Item {key!r} not recognized inside {cls.__name__} at {prefix}"
                ) from None

            kwargs[f] = _load(value, fieldtype, keyprefix, depth_limit)

        try:
            return cls(**kwargs)
        except TypeError as e:
            missing = [
                f.name
                for f in dataclasses.fields(cls)
                if f.name not in kwargs
                and f.default is dataclasses.MISSING
                and f.default_factory is dataclasses.MISSING
                and f.init
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


def _load(value, fieldtype, keyprefix, depth_limit):
    # FIXME: isinstance(value, fieldtype) requires a pre-check because it can't
    # do dict[str, int] -- but we can't just check for being a type either,
    # because Optional[str] or SomeType | None works well with isinstance

    # Things would be much easier if we could do `isinstance(value, fieldtype)`
    # not just for the working (42, int) and (42, Optional[int]) and ({}, dict
    # | list), but also for the non-working ({"x":1}, dict[str, int]) and more
    # complex cases of that style: "isinstance() argument 2 cannot be a
    # parameterized generic".
    #
    # As the offending parameterized generics can not be just the top-level
    # annotation but also part of a union, we have to dissect them:
    fieldtypes = _unpack_union(fieldtype)

    # As we have a list, we try to match it greedily.
    for fieldtype in fieldtypes:
        if not isinstance(fieldtype, type):
            raise TypeError(
                "Annotation can not be processed: Can only process unions over types"
            )

        if isinstance(value, fieldtype):
            # This case covers
            # * "hello" for str
            # * MyLoadable(…) for MyLoadable (which is something odd but allowed)
            #
            # It'd also tolerate
            # * 52 for Optional[int]
            # * None for MyLoadable | None
            # but those are taken care of already by _unpack_union
            return value

        if isinstance(value, dict) and issubclass(fieldtype, LoadStoreClass):
            # FIXME: allow annotating single distinct non-dict-value, eg.
            # like Cargo.toml's implicit version in dependencies. (Right
            # now we can do this can be done at the parent level, maybe
            # that suffices?).
            if depth_limit == 0:
                raise ValueError("Nesting exceeded limit in {keyprefix}")
            return fieldtype.load(value, prefix=keyprefix, depth_limit=depth_limit - 1)

        # FIXME:
        # - For lists and dicts, evaluate items (can be deferred until we actually have any)
        # - Special treatment for bytes: Accept {"acii": "hello"} and {"hex": "001122"}
        # - Special treatment for Path (probably with new filename argument)
        # - In union handling, support multiple, possibly fanning out by disambiguator keys?

    expected = " or ".join(
        f"dict (representing {t.__name__})"
        if issubclass(t, LoadStoreClass)
        else t.__name__
        for t in fieldtypes
    )
    raise ValueError(
        f"Type mismatch on {keyprefix}: Expected {expected}, found {type(value).__name__}"
    )


def _unpack_union(annotation) -> tuple:
    """If the annotation is a Union (including Optional), this returns a tuple
    of union'd types; otherwise a tuple containing only the annotation.

    When Python 3.13 support is dropped, this can be simplified based on
    type(Optional[str]) being Union.


    >>> from typing import *
    >>> _unpack_union(str) == (str,)
    True
    >>> _unpack_union(str | None) == (str, type(None))
    True
    >>> _unpack_union(Optional[dict[str, str]]) == (dict[str, str], type(None))
    True
    """
    if sys.version_info >= (3, 14):
        if isinstance(annotation, Union):
            return annotation.__args__
    else:
        if type(annotation).__name__ in ("_UnionGenericAlias", "UnionType"):
            return annotation.__args__
    return (annotation,)
