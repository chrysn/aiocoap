class ExtensibleEnumMeta(type):
    def __init__(self, name, bases, dict):
        for k, v in dict.items():
            if k.startswith('_'):
                continue
            if callable(v):
                continue
            setattr(self, k, self(v))
        type.__init__(self, name, bases, dict)

class ExtensibleIntEnum(int, metaclass=ExtensibleEnumMeta):
    """Similar to Python3.4's enum.IntEnum, this type can be used for named
    numbers which are not comprehensively known, like CoAP option numbers.

    As an implementation simplification, this type does not guarantee that
    objects are singletons; they can only be reasonably compared with ==
    instead of `is`, and can not have properties stored in the singletons."""

    def __add__(self, delta):
        return type(self)(int(self) + delta)

    def __repr__(self):
        return '<%s %d>'%(type(self).__name__, self)
