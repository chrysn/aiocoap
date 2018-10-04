from collections import namedtuple, defaultdict
import functools
import inspect
import abc

import json
import cbor

from aiocoap import resource, numbers, interfaces
from aiocoap import GET, PUT, POST, Message, CONTENT, CHANGED
from aiocoap.error import BadRequest, UnsupportedContentFormat, UnallowedMethod


_ContenttypeRenderedHandler = namedtuple("_ContenttypeRenderedHandler", ("method", "accept", "contentformat", "implementation", "responseformat"))

class _ContenttypeRenderedMeta(abc.ABCMeta): # FIXME i suppose i can't make that a mixin? it feels odd that i have to state that here just because the classes that use it happen to also implement abcmeta interfaces
    def __new__(cls, *args):
        ret = super().__new__(cls, *args)
        ret._cls_setup()
        return ret

# this could become an alternative to the resource.Resource currently implemented in aiocoap.resource

class ContenttypeRendered(resource._ExposesWellknownAttributes, interfaces.Resource, metaclass=_ContenttypeRenderedMeta):
    @classmethod
    def _cls_setup(cls):
        # __new__ code moved in here to use __ properties
        cls.__handlers = defaultdict(lambda: {})
        for member in vars(cls).values():
            if isinstance(member, _ContenttypeRenderedHandler):
                for accept in member.accept:
                    for contentformat in member.contentformat:
                        cls.__handlers[member.method][(accept, contentformat)] = (member.implementation, member.responseformat)

    @staticmethod
    def get_handler(accept, *, default=False):
        """Decorate a method with this to make it the GET handler for a given
        method and Accept value (or additionally the empty one if default=True).

        FIXME move to ContenttypeRendered

        Methods that accept a payload will get the payload passed as an
        argument, and be decided based on the Content-Format header (with the
        Accept header being ignored; possibly, that's a reasons to split this
        decorator up per-method).

        The method will not be usable by its name any more. It is recommended
        to use a double-underscore name for thusly decorated methods (eg.
        __get_plain).

        The method has some freedom in the types it may return (None is treated
        as an empty payload, strings are encoded in UTF-8). It is unclear yet
        whether more complex conversions (eg. JSON, CBOR) will be supported by
        this or need additonal decorators."""
        def wrapper(func):
            cf = numbers.media_types_rev[accept]
            return _ContenttypeRenderedHandler(GET, (cf, None) if default else (cf,), (None,), func, cf)
        return wrapper

    @staticmethod
    def put_handler(contentformat, *, default=False):
        def wrapper(func):
            cf = numbers.media_types_rev[contentformat]
            return _ContenttypeRenderedHandler(PUT, (None,), (cf, None) if default else (cf,), func, None)
        return wrapper

    @staticmethod
    def empty_post_handler():
        # i suppose this'll be replaced with something more generic when i add something that needs request or response payloads
        def wrapper(func):
            return _ContenttypeRenderedHandler(POST, (None,), (None,), func, None)
        return wrapper

    async def needs_blockwise_assembly(self, request):
        return True

    async def render(self, request):
        cf = request.opt.content_format
        acc = request.opt.accept
        raise_class = UnallowedMethod
        method_would_have_worked = False

        # FIXME: manually walking the MRO is not a nice way to go about this;
        # is there no other way to query the registered handlers according to
        # the regular inheritance patterns?
        for cls in type(self).mro():
            if not issubclass(cls, ContenttypeRendered):
                continue
            for_method = cls.__handlers.get(request.code, None)
            if for_method is None:
                continue
            raise_class = UnsupportedContentFormat
            handler, responseformat = for_method.get((acc, cf), (None, None))
            if handler is not None:
                break
        else:
            raise raise_class()

        sig = inspect.signature(handler)
        if any(i != 0 and a.kind not in (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.VAR_KEYWORD) for (i, a) in enumerate(sig.parameters.values())):
            # there's a positional argument
            args = (request.payload,)
        else:
            if request.payload:
                raise BadRequest("Unexpected payload")
            args = ()
        # FIXME add query as kwargs?
        payload = handler(self, *args)

        if payload is None:
            payload = b""
        elif isinstance(payload, str):
            payload = payload.encode('utf8')

        return Message(
                code={GET: CONTENT, PUT: CHANGED}[request.code],
                payload=payload,
                content_format=responseformat
                )

class ObservableContenttypeRendered(ContenttypeRendered, interfaces.ObservableResource):
    def __init__(self):
        super().__init__()

        self._callbacks = set()

    async def add_observation(self, request, serverobservation):
        callback = serverobservation.trigger
        self._callbacks.add(callback)
        remover = functools.partial(self._callbacks.remove, callback)
        serverobservation.accept(remover)

    def add_valuechange_callback(self, cb):
        self._callbacks.add(cb)

    def value_changed(self):
        for c in self._callbacks:
            c()


class SenmlResource(ObservableContenttypeRendered):
    """A resource that has its state in .value; this class implements SenML
    getters and setters as well as plain text.

    Implementors need to provide a .value instance property as well as
    .jsonsenml_key / .cborsenml_key class properties for picking the right
    value key in the respective SenML serialization, and a .valuetype type that
    is used both for converting any text/plain'ly PUT string as well as for
    filtering (typically copy-constructing) data from SenML."""

    @ContenttypeRendered.get_handler('application/senml+json')
    def __jsonsenml_get(self):
        return json.dumps([{self.jsonsenml_key: self.value}])

    @ContenttypeRendered.get_handler('application/senml+cbor')
    def __cborsenml_get(self):
        return cbor.dumps([{self.cborsenml_key: self.value}])

    @ContenttypeRendered.get_handler('text/plain;charset=utf-8', default=True)
    def __textplain_get(self):
        return str(self.value)

    @ContenttypeRendered.put_handler('application/senml+json')
    def __jsonsenml_set(self, new):
        try:
            self.value = self.valuetype(new[self.jsonsenml_key])
        except (KeyError, ValueError):
            raise BadRequest()

    @ContenttypeRendered.put_handler('application/senml+cbor')
    def __cborsenml_set(self, value):
        try:
            self.value = self.valuetype(new[self.cborsenml_key])
        except (KeyError, ValueError):
            raise BadRequest()

    @ContenttypeRendered.put_handler('text/plain;charset=utf-8', default=True)
    def __textplain_set(self, new):
        try:
            self.value = self.valuetype(new.decode('utf8').strip())
        except ValueError:
            raise BadRequest()

class BooleanResource(SenmlResource):
    jsonsenml_key = "vb"
    cborsenml_key = 4
    valuetype = bool

    @ContenttypeRendered.get_handler('text/plain;charset=utf-8', default=True)
    def __textplain_get(self):
        return "01"[self.value]

    @ContenttypeRendered.put_handler('text/plain;charset=utf-8', default=True)
    def __textplain_set(self, new):
        try:
            self.value = {"0": False, "1": True}[new.decode('utf8').strip()]
        except (KeyError, ValueError):
            raise BadRequest()

class FloatResource(SenmlResource):
    jsonsenml_key = "v"
    cborsenml_key = 2
    valuetype = float

class StringResource(SenmlResource):
    jsonsenml_key = "vs"
    cborsenml_key = 3
    valuetype = str

class SubsiteBatch(ObservableContenttypeRendered):
    """An implementation of a CoRE interfaces batch that is the root resource
    of a subsite

    This currently depends on being added to the site after all other
    resources; it could enumerate them later, but it installs its own
    value_changed callbacks of other members at initialization time."""

    if_ = 'core.b'

    def __init__(self, site):
        self.site = site
        super().__init__()

        # FIXME this ties in directly into resource.Site's privates, AND it
        # should actually react to changes in the site, AND overriding the
        # callback to install an own hook is not compatible with any other
        # ObservableResource implementations
        for subres in self.site._resources.values():
            if isinstance(subres, ObservableContenttypeRendered):
                subres.add_valuechange_callback(self.value_changed)
        for subsite in self.site._subsites.values():
            if not isinstance(subsite, resource.Site):
                continue # can't access privates
            if () not in subsite._resources:
                continue # no root, better not try
            rootres = subsite._resources[()]
            if not isinstance(rootres, SubsiteBatch):
                continue
            rootres.add_valuechange_callback(self.value_changed)

    def __get_records(self):
        records = []
        # FIXME this ties in directly into resource.Site's privates
        for path, subres in self.site._resources.items():
            if isinstance(subres, SenmlResource): # this conveniently filters out self as well
                records.append({'n': '/'.join(path), subres.jsonsenml_key: subres.value})
        print(self.site, vars(self.site))
        for path, subsite in self.site._subsites.items():
            if not isinstance(subsite, resource.Site):
                continue # can't access privates
            if () not in subsite._resources:
                continue # no root, better not try
            rootres = subsite._resources[()]
            if not isinstance(rootres, SubsiteBatch):
                continue
            for r in rootres.__get_records():
                r = dict(**r)
                r['n'] = "/".join(path) + "/" + r['n']
                records.append(r)
        return records

    @ContenttypeRendered.get_handler('application/senml+json', default=True)
    def __regular_get(self):
        return json.dumps(self.__get_records())


class PythonBacked(SenmlResource):
    """Provides a .value stored in regular Python, but pulls the
    .value_changed() trigger on every change"""

    def _set_value(self, value):
        changed = not hasattr(self, '_value') or self._value != value
        self._value = value
        if changed:
            self.value_changed()

    value = property(lambda self: self._value, _set_value)
