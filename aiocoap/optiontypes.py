# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import abc
import collections

from .numbers.contentformat import ContentFormat


def _to_minimum_bytes(value):
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


class OptionType(metaclass=abc.ABCMeta):
    """Interface for decoding and encoding option values

    Instances of :class:`OptionType` are collected in a list in a
    :attr:`.Message.opt` :class:`.Options` object, and provide a translation
    between the CoAP octet-stream (accessed using the
    :meth:`encode()`/:meth:`decode()` method pair) and the interpreted value
    (accessed via the :attr:`value` attribute).

    Note that OptionType objects usually don't need to be handled by library
    users; the recommended way to read and set options is via the Options
    object'sproperties (eg. ``message.opt.uri_path = ('.well-known',
    'core')``)."""

    @abc.abstractmethod
    def __init__(self, number, value):
        """Set the `self.name` and `self.value` attributes"""

    @abc.abstractmethod
    def encode(self):
        """Return the option's value in serialzied form"""

    @abc.abstractmethod
    def decode(self, rawdata):
        """Set the option's value from the bytes in rawdata"""

    def _repr_html_(self):
        import html

        return f"<tt>{html.escape(repr(self))}</tt>"


class StringOption(OptionType):
    """String CoAP option - used to represent string options. Always encoded in
    UTF8 per CoAP specification."""

    def __init__(self, number, value=""):
        self.value = value
        self.number = number

    def encode(self):
        # FIXME: actually, this should be utf8 of the net-unicode form (maybe it is)
        rawdata = self.value.encode("utf-8")
        return rawdata

    def decode(self, rawdata):
        self.value = rawdata.decode("utf-8")

    def __str__(self):
        return self.value

    def _repr_html_(self):
        import html

        return f"<tt>{html.escape(repr(self.value))}</tt>"


class OpaqueOption(OptionType):
    """Opaque CoAP option - used to represent options that just have their
    uninterpreted bytes as value."""

    def __init__(self, number, value=b""):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = self.value
        return rawdata

    def decode(self, rawdata):
        self.value = rawdata

    def __str__(self):
        return repr(self.value)

    def _repr_html_(self):
        return f"<tt>{self.value.hex()}</tt>"


class UintOption(OptionType):
    """Uint CoAP option - used to represent integer options."""

    def __init__(self, number, value=0):
        self.value = value
        self.number = number

    def encode(self):
        return _to_minimum_bytes(int(self.value))

    def decode(self, rawdata):
        self.value = int.from_bytes(rawdata, "big")

    def __str__(self):
        return str(self.value)

    def _repr_html_(self):
        import html

        return f"<tt>{html.escape(repr(self.value))}</tt>"


class TypedOption(OptionType, metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def type(self) -> type:
        """Checked type of the option"""

    def __init__(self, number, value=None):
        self.number = number
        # FIXME when is this ever initialized without value?
        if value is not None:
            self.value = value

    value = property(
        lambda self: self._value, lambda self, value: self._set_from_opt_value(value)
    )

    def _set_from_opt_value(self, value: object):
        """Convert a value set as ``message.opt.option_name = value`` into the
        stored value. By default, this does an eager isinstance check on the
        value (anticipating that encoding an unsuitable value would otherwise
        fail at a hard-to-debug location)."""
        if not isinstance(value, self.type):
            raise ValueError(
                "Setting values of type %s is not supported on this option"
                % type(value)
            )
        self._value = value

    def __str__(self):
        return str(self.value)

    def _repr_html_(self):
        if hasattr(self.value, "_repr_html_"):
            return self.value._repr_html_()
        else:
            import html

            return f"<tt>{html.escape(repr(self.value))}</tt>"


class BlockOption(TypedOption):
    """Block CoAP option - special option used only for Block1 and Block2 options.
    Currently it is the only type of CoAP options that has
    internal structure.

    That structure (BlockwiseTuple) covers not only the block options of
    RFC7959, but also the BERT extension of RFC8323. If the reserved size
    exponent 7 is used for purposes incompatible with BERT, the implementor
    might want to look at the context dependent option number
    interpretations which will hopefully be in place for Signaling (7.xx)
    messages by then."""

    class BlockwiseTuple(
        collections.namedtuple(
            "_BlockwiseTuple", ["block_number", "more", "size_exponent"]
        )
    ):
        @property
        def size(self):
            return 2 ** (min(self.size_exponent, 6) + 4)

        @property
        def start(self):
            """The byte offset in the body indicated by block number and size.

            Note that this calculation is only valid for descriptive use and
            Block2 control use. The semantics of block_number and size in
            Block1 control use are unrelated (indicating the acknowledged block
            number in the request Block1 size and the server's preferred block
            size), and must not be calculated using this property in that
            case."""
            return self.block_number * self.size

        @property
        def is_bert(self):
            """True if the exponent is recognized to signal a BERT message."""
            return self.size_exponent == 7

        def is_valid_for_payload_size(self, payloadsize):
            if self.is_bert:
                if self.more:
                    return payloadsize % 1024 == 0
                return True
            else:
                if self.more:
                    return payloadsize == self.size
                else:
                    return payloadsize <= self.size

        def reduced_to(self, maximum_exponent):
            """Return a BlockwiseTuple whose exponent is capped to the given
            maximum_exponent

            >>> initial = BlockOption.BlockwiseTuple(10, 0, 5)
            >>> initial == initial.reduced_to(6)
            True
            >>> initial.reduced_to(3)
            BlockwiseTuple(block_number=40, more=0, size_exponent=3)
            """
            if maximum_exponent >= self.size_exponent:
                return self
            if maximum_exponent == 6 and self.size_exponent == 7:
                return (self.block_number, self.more, 6)
            increasednumber = self.block_number << (
                min(self.size_exponent, 6) - maximum_exponent
            )
            return type(self)(increasednumber, self.more, maximum_exponent)

    type = BlockwiseTuple

    def encode(self):
        as_integer = (
            (self.value.block_number << 4)
            + (self.value.more * 0x08)
            + self.value.size_exponent
        )
        return _to_minimum_bytes(as_integer)

    def decode(self, rawdata):
        as_integer = int.from_bytes(rawdata, "big")
        self.value = self.BlockwiseTuple(
            block_number=(as_integer >> 4),
            more=bool(as_integer & 0x08),
            size_exponent=(as_integer & 0x07),
        )

    def _set_from_opt_value(self, value):
        # Casting it through the constructor makes it easy to set the option as
        # `(num, more, sz)` without having to pick the type out of a very long
        # module name
        super()._set_from_opt_value(self.type(*value))


class ContentFormatOption(TypedOption):
    """Type of numeric options whose number has :class:`ContentFormat`
    semantics"""

    type = ContentFormat

    def encode(self):
        return _to_minimum_bytes(int(self.value))

    def decode(self, rawdata):
        as_integer = int.from_bytes(rawdata, "big")
        self._value = ContentFormat(as_integer)

    def _set_from_opt_value(self, value):
        super()._set_from_opt_value(ContentFormat(value))
