# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Basic resource implementations

A resource in URL / CoAP / REST terminology is the thing identified by a URI.

Here, a :class:`.Resource` is the place where server functionality is
implemented. In many cases, there exists one persistent Resource object for a
given resource (eg. a ``TimeResource()`` is responsible for serving the
``/time`` location). On the other hand, an aiocoap server context accepts only
one thing as its serversite, and that is a Resource too (typically of the
:class:`Site` class).

Resources are most easily implemented by deriving from :class:`.Resource` and
implementing ``render_get``, ``render_post`` and similar coroutine methods.
Those take a single request message object and must return a
:class:`aiocoap.Message` object or raise an
:class:`.error.RenderableError` (eg. ``raise UnsupportedMediaType()``).

To serve more than one resource on a site, use the :class:`Site` class to
dispatch requests based on the Uri-Path header.
"""

import hashlib
import warnings

from . import message
from . import meta
from . import error
from . import interfaces
from . import numbers
from .pipe import Pipe

def hashing_etag(request, response):
    """Helper function for render_get handlers that allows them to use ETags based
    on the payload's hash value

    Run this on your request and response before returning from render_get; it is
    safe to use this function with all kinds of responses, it will only act on
    2.05 Content messages (and those with no code set, which defaults to that
    for GET requests). The hash used are the first 8 bytes of the sha1 sum of
    the payload.

    Note that this method is not ideal from a server performance point of view
    (a file server, for example, might want to hash only the stat() result of a
    file instead of reading it in full), but it saves bandwith for the simple
    cases.

    >>> from aiocoap import *
    >>> req = Message(code=GET)
    >>> hash_of_hello = b'\\xaa\\xf4\\xc6\\x1d\\xdc\\xc5\\xe8\\xa2'
    >>> req.opt.etags = [hash_of_hello]
    >>> resp = Message(code=CONTENT)
    >>> resp.payload = b'hello'
    >>> hashing_etag(req, resp)
    >>> resp                                            # doctest: +ELLIPSIS
    <aiocoap.Message at ... 2.03 Valid ... 1 option(s)>
    """

    if response.code != numbers.codes.CONTENT and response.code is not None:
        return

    response.opt.etag = hashlib.sha1(response.payload).digest()[:8]
    if request.opt.etags is not None and response.opt.etag in request.opt.etags:
        response.code = numbers.codes.VALID
        response.payload = b''

class _ExposesWellknownAttributes:
    def get_link_description(self):
        # FIXME which formats are acceptable, and how much escaping and
        # list-to-separated-string conversion needs to happen here
        ret = {}
        if hasattr(self, 'ct'):
            ret['ct'] = str(self.ct)
        if hasattr(self, 'rt'):
            ret['rt'] = self.rt
        if hasattr(self, 'if_'):
            ret['if'] = self.if_
        return ret

class Resource(_ExposesWellknownAttributes, interfaces.Resource):
    """Simple base implementation of the :class:`interfaces.Resource`
    interface

    The render method delegates content creation to ``render_$method`` methods
    (``render_get``, ``render_put`` etc), and responds appropriately to
    unsupported methods. Those messages may return messages without a response
    code, the default render method will set an appropriate successful code
    ("Content" for GET/FETCH, "Deleted" for DELETE, "Changed" for anything
    else). The render method will also fill in the request's no_response code
    into the response (see :meth:`.interfaces.Resource.render`) if none was
    set.

    Moreover, this class provides a ``get_link_description`` method as used by
    .well-known/core to expose a resource's ``.ct``, ``.rt`` and ``.if_``
    (alternative name for ``if`` as that's a Python keyword) attributes.
    Details can be added by overriding the method to return a more
    comprehensive dictionary, and resources can be hidden completely by
    returning None.
    """

    async def needs_blockwise_assembly(self, request):
        return True

    async def render(self, request):
        if not request.code.is_request():
            raise error.UnsupportedMethod()
        m = getattr(self, 'render_%s' % str(request.code).lower(), None)
        if not m:
            raise error.UnallowedMethod()

        response = await m(request)

        if response is message.NoResponse:
            warnings.warn("Returning NoResponse is deprecated, please return a"
                          " regular response with a no_response option set.",
                          DeprecationWarning)
            response = message.Message(no_response=26)

        if response.code is None:
            if request.code in (numbers.codes.GET, numbers.codes.FETCH):
                response_default = numbers.codes.CONTENT
            elif request.code == numbers.codes.DELETE:
                response_default = numbers.codes.DELETED
            else:
                response_default = numbers.codes.CHANGED
            response.code = response_default

        if response.opt.no_response is None:
            response.opt.no_response = request.opt.no_response

        return response

    async def render_to_pipe(self, request: Pipe):
        # Silence the deprecation warning
        if isinstance(self, interfaces.ObservableResource):
            # See interfaces.Resource.render_to_pipe
            return await interfaces.ObservableResource._render_to_pipe(self, request)
        return await interfaces.Resource._render_to_pipe(self, request)

class ObservableResource(Resource, interfaces.ObservableResource):
    def __init__(self):
        super(ObservableResource, self).__init__()
        self._observations = set()

    async def add_observation(self, request, serverobservation):
        self._observations.add(serverobservation)
        def _cancel(self=self, obs=serverobservation):
            self._observations.remove(serverobservation)
            self.update_observation_count(len(self._observations))
        serverobservation.accept(_cancel)
        self.update_observation_count(len(self._observations))

    def update_observation_count(self, newcount):
        """Hook into this method to be notified when the number of observations
        on the resource changes."""

    def updated_state(self, response=None):
        """Call this whenever the resource was updated, and a notification
        should be sent to observers."""

        for o in self._observations:
            o.trigger(response)

    def get_link_description(self):
        link = super(ObservableResource, self).get_link_description()
        link['obs'] = None
        return link

    async def render_to_pipe(self, request: Pipe):
        # Silence the deprecation warning
        return await interfaces.ObservableResource._render_to_pipe(self, request)

def link_format_to_message(request, linkformat,
        default_ct=numbers.ContentFormat.LINKFORMAT):
    """Given a LinkFormat object, render it to a response message, picking a
    suitable conent format from a given request.

    It returns a Not Acceptable response if something unsupported was queried.

    It makes no attempt to modify the URI reference literals encoded in the
    LinkFormat object; they have to be suitably prepared by the caller."""

    ct = request.opt.accept
    if ct is None:
        ct = default_ct

    if ct == numbers.ContentFormat.LINKFORMAT:
        payload = str(linkformat).encode('utf8')
    else:
        return message.Message(code=numbers.NOT_ACCEPTABLE)

    return message.Message(payload=payload, content_format=ct)

# Convenience attribute to set as ct on resources that use
# link_format_to_message as their final step in the request handler
link_format_to_message.supported_ct = " ".join(str(int(x)) for x in (
        numbers.ContentFormat.LINKFORMAT,
        ))

class WKCResource(Resource):
    """Read-only dynamic resource list, suitable as .well-known/core.

    This resource renders a link_header.LinkHeader object (which describes a
    collection of resources) as application/link-format (RFC 6690).

    The list to be rendered is obtained from a function passed into the
    constructor; typically, that function would be a bound
    Site.get_resources_as_linkheader() method.

    This resource also provides server `implementation information link`_;
    server authors are invited to override this by passing an own URI as the
    `impl_info` parameter, and can disable it by passing None.

    .. _`implementation information link`: https://tools.ietf.org/html/draft-bormann-t2trg-rel-impl-00"""

    ct = link_format_to_message.supported_ct

    def __init__(self, listgenerator, impl_info=meta.library_uri, **kwargs):
        super().__init__(**kwargs)
        self.listgenerator = listgenerator
        self.impl_info = impl_info

    async def render_get(self, request):
        links = self.listgenerator()

        if self.impl_info is not None:
            from .util.linkformat import Link
            links.links = links.links + [Link(href=self.impl_info, rel="impl-info")]

        filters = []
        for q in request.opt.uri_query:
            try:
                k, v = q.split('=', 1)
            except ValueError:
                continue # no =, not a relevant filter

            if v.endswith('*'):
                def matchexp(x, v=v):
                    return x.startswith(v[:-1])
            else:
                def matchexp(x, v=v):
                    return x == v

            if k in ('rt', 'if', 'ct'):
                filters.append(lambda link: any(matchexp(part) for part in (" ".join(getattr(link, k, ()))).split(" ")))
            elif k in ('href',): # x.href is single valued
                filters.append(lambda link: matchexp(getattr(link, k)))
            else:
                filters.append(lambda link: any(matchexp(part) for part in getattr(link, k, ())))

        while filters:
            links.links = filter(filters.pop(), links.links)
        links.links = list(links.links)

        response = link_format_to_message(request, links)

        if request.opt.uri_query and not links.links and \
                request.remote.is_multicast_locally:
            if request.opt.no_response is None:
                # If the filter does not match, multicast requests should not
                # be responded to -- that's equivalent to a "no_response on
                # 2.xx" option.
                response.opt.no_response = 0x02

        return response

class PathCapable:
    """Class that indicates that a resource promises to parse the uri_path
    option, and can thus be given requests for :meth:`.render`-ing that
    contain a uri_path"""

class Site(interfaces.ObservableResource, PathCapable):
    """Typical root element that gets passed to a :class:`Context` and contains
    all the resources that can be found when the endpoint gets accessed as a
    server.

    This provides easy registration of statical resources. Add resources at
    absolute locations using the :meth:`.add_resource` method.

    For example, the site at

    >>> site = Site()
    >>> site.add_resource(["hello"], Resource())

    will have requests to </hello> rendered by the new resource.

    You can add another Site (or another instance of :class:`PathCapable`) as
    well, those will be nested and integrally reported in a WKCResource. The
    path of a site should not end with an empty string (ie. a slash in the URI)
    -- the child site's own root resource will then have the trailing slash
    address.  Subsites can not have link-header attributes on their own (eg.
    `rt`) and will never respond to a request that does not at least contain a
    single slash after the the given path part.

    For example,

    >>> batch = Site()
    >>> batch.add_resource(["light1"], Resource())
    >>> batch.add_resource(["light2"], Resource())
    >>> batch.add_resource([], Resource())
    >>> s = Site()
    >>> s.add_resource(["batch"], batch)

    will have the three created resources rendered at </batch/light1>,
    </batch/light2> and </batch/>.

    If it is necessary to respond to requests to </batch> or report its
    attributes in .well-known/core in addition to the above, a non-PathCapable
    resource can be added with the same path. This is usually considered an odd
    design, not fully supported, and for example doesn't support removal of
    resources from the site.
    """

    def __init__(self):
        self._resources = {}
        self._subsites = {}

    async def needs_blockwise_assembly(self, request):
        try:
            child, subrequest = self._find_child_and_pathstripped_message(request)
        except KeyError:
            return True
        else:
            return await child.needs_blockwise_assembly(subrequest)

    def _find_child_and_pathstripped_message(self, request):
        """Given a request, find the child that will handle it, and strip all
        path components from the request that are covered by the child's
        position within the site. Returns the child and a request with a path
        shortened by the components in the child's path, or raises a
        KeyError.

        While producing stripped messages, this adds a ._original_request_uri
        attribute to the messages which holds the request URI before the
        stripping is started. That allows internal components to access the
        original URI until there is a variation of the request API that allows
        accessing this in a better usable way."""

        original_request_uri = getattr(request, '_original_request_uri',
                request.get_request_uri(local_is_server=True))

        if request.opt.uri_path in self._resources:
            stripped = request.copy(uri_path=())
            stripped._original_request_uri = original_request_uri
            return self._resources[request.opt.uri_path], stripped

        if not request.opt.uri_path:
            raise KeyError()

        remainder = [request.opt.uri_path[-1]]
        path = request.opt.uri_path[:-1]
        while path:
            if path in self._subsites:
                res = self._subsites[path]
                if remainder == [""]:
                    # sub-sites should see their root resource like sites
                    remainder = []
                stripped = request.copy(uri_path=remainder)
                stripped._original_request_uri = original_request_uri
                return res, stripped
            remainder.insert(0, path[-1])
            path = path[:-1]
        raise KeyError()

    async def render(self, request):
        try:
            child, subrequest = self._find_child_and_pathstripped_message(request)
        except KeyError:
            raise error.NotFound()
        else:
            return await child.render(subrequest)

    async def add_observation(self, request, serverobservation):
        try:
            child, subrequest = self._find_child_and_pathstripped_message(request)
        except KeyError:
            return

        try:
            await child.add_observation(subrequest, serverobservation)
        except AttributeError:
            pass

    def add_resource(self, path, resource):
        if isinstance(path, str):
            raise ValueError("Paths should be tuples or lists of strings")
        if isinstance(resource, PathCapable):
            self._subsites[tuple(path)] = resource
        else:
            self._resources[tuple(path)] = resource

    def remove_resource(self, path):
        try:
            del self._subsites[tuple(path)]
        except KeyError:
            del self._resources[tuple(path)]

    def get_resources_as_linkheader(self):
        from .util.linkformat import Link, LinkFormat

        links = []

        for path, resource in self._resources.items():
            if hasattr(resource, "get_link_description"):
                details = resource.get_link_description()
            else:
                details = {}
            if details is None:
                continue
            lh = Link('/' + '/'.join(path), **details)

            links.append(lh)

        for path, resource in self._subsites.items():
            if hasattr(resource, "get_resources_as_linkheader"):
                for l in resource.get_resources_as_linkheader().links:
                    links.append(Link('/' + '/'.join(path) + l.href, l.attr_pairs))
        return LinkFormat(links)

    async def render_to_pipe(self, request: Pipe):
        try:
            child, subrequest = self._find_child_and_pathstripped_message(request.request)
        except KeyError:
            raise error.NotFound()
        else:
            # FIXME consider carefully whether this switching-around is good.
            # It probably is.
            request.request = subrequest
            return await child.render_to_pipe(request)
