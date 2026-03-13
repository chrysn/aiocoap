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
...     z: dict[str, int]
>>> Top.load({"x": "test", "y": {"some-text": "one", "some-number": 42}, "z": {"a": 1}})
Top(x='test', y=Inner(some_text='one', some_number=42), z={'a': 1})
"""

import dataclasses
import types
from typing import Self, Union, Optional
from pathlib import Path
import sys


class LoadStoreClass:
    @classmethod
    def load(
        cls,
        data: dict,
        *,
        depth_limit: int = 16,
        basefile: Optional[Path] = None,
        _prefix: Optional[str] = None,
    ) -> Self:
        """Creates an instance from the given data dictionary.

        Keys are used to populate fields like in the initializer; dashes ("-")
        in names are replaced with underscores ("_") so that Python-idiomatic
        field names (in snake_case) can be used with TOML idiomatic item names
        (in kebab-case).

        Values are type-checked against the annotations, and unknown fields are
        disallowed. When annotations indicate another ``LoadStoreClass``,
        initialization recurses into that type up to a depth limit.

        The ``basefile`` is used for error messages, and to construct ``Path``
        items as relative to the file name given there. (For example, if
        ``basefile=Path("config.d/test.json")``, a value of ``"test2.json"``
        will be represented as ``Path("config.d/test2.json")``). It also serves
        as a starting point for the error location indication, which is built
        into ``_prefix`` in recursion as a vague path-like expression like
        ``test.json key/key[key]``.

        This reliably raises ``ValueError`` or its subtypes on unacceptable
        data as long as the class is set up in a supported way.
        """

        assert dataclasses.is_dataclass(cls)

        if _prefix is None:
            if basefile is not None:
                prefix = f"{basefile} "
            else:
                prefix = ""
        else:
            prefix = f"{_prefix}/"

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

            kwargs[f] = _load(value, fieldtype, keyprefix, depth_limit, basefile)

        try:
            return cls(**kwargs)
        except ValueError as e:
            raise ValueError(
                f"Error constructing {cls.__name__} at {prefix}: {e}"
            ) from e
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

    @classmethod
    def load_from_file(cls, file: Path | str) -> Self:
        """Loads an item from a file.

        The file is opened, and the file type is determined from the extension.
        The set of supported file types may vary by installed packages and
        Python version.
        """
        file = Path(file)

        match file.suffix:
            # Cases don't need error handling if they raise ValueError type
            # exceptions, and if imports are from the standard library in the
            # supported Python versions
            case ".json":
                import json

                with file.open("rb") as opened:
                    data = json.load(opened)
            case ".toml":
                import tomllib

                with file.open("rb") as opened:
                    data = tomllib.load(opened)
            case ".yaml" | ".yml":
                try:
                    import yaml
                except ImportError:
                    raise ValueError(
                        "Loading configuration from YAML files requires the `pyyaml` package installed."
                    )

                with file.open("rb") as opened:
                    data = yaml.safe_load(opened)
            case ".diag" | ".edn":
                try:
                    import cbor_diag
                    import cbor2
                except ImportError:
                    raise ValueError(
                        "Loading configuration from CBOR EDN (Diagnostic Notation) files requires the `cbor-diag` and `cbor2` packages installed."
                    )

                data = cbor2.loads(
                    cbor_diag.diag2cbor(file.read_text(encoding="utf-8"))
                )
            case extension:
                raise ValueError(
                    f"Unsupported extension {extension!r}. Supported are .toml, .json and (depending on installed modules) .yml / .yaml and .edn / .diag"
                )

        return cls.load(data, basefile=file)


def _load(value, fieldtype, keyprefix, depth_limit, basefile):
    if depth_limit == 0:
        raise ValueError("Nesting exceeded limit in {keyprefix}")

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
        if isinstance(fieldtype, types.GenericAlias):
            if fieldtype.__origin__ is dict and len(fieldtype.__args__) == 2:
                if fieldtype.__args__[0] is not str:
                    raise TypeError(
                        "Annotations of dict are limited to using str as key."
                    )
                if not isinstance(value, dict):
                    # Clear mismatch, continue searching
                    continue
                # Locking in now: At this point, a dict was promised, and we
                # expect it to be. (Might revisit if this is impractical, but I
                # guess that alternatives would be more specific and just
                # picked before the generic option).
                non_string_keys = [k for k in value.keys() if not isinstance(k, str)]
                if non_string_keys:
                    raise ValueError(
                        f"Non-string key(s) found at {keyprefix}: {non_string_keys}"
                    )
                return {
                    k: _load(
                        v,
                        fieldtype.__args__[1],
                        f"{keyprefix}[{k}]",
                        depth_limit - 1,
                        basefile,
                    )
                    for (k, v) in value.items()
                }
            else:
                raise TypeError(
                    "Annotations of generic aliases are limited to the shape dict[K, V]."
                )

        if not isinstance(fieldtype, type):
            raise TypeError(
                "Annotation can not be processed: Can only process unions over types and some generic aliases (eg. dict[str, str])"
            )

        if fieldtype is Path and isinstance(value, str):
            if basefile is None:
                return Path(value)
            else:
                return basefile.parent / value

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
            return fieldtype.load(
                value, _prefix=keyprefix, depth_limit=depth_limit - 1, basefile=basefile
            )

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
