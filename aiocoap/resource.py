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
implementing ``render_GET``, ``render_POST`` and similar coroutine methods.
Those take a single request message object and must return a
:class:`aiocoap.Message` object.

To serve more than one resource on a site, use the :class:`Site` class to
dispatch requests based on the Uri-Path header.
"""

import hashlib
import asyncio

from . import error
from . import interfaces
from . import numbers

def hashing_etag(request, response):
    """Helper function for do_GET handlers that allows them to use ETags based
    on the payload's hash value

    Run this on your request and response before returning from do_GET; it is
    safe to use this function with all kinds of responses, it will only act on
    2.05 Content. The hash used are the first 8 bytes of the sha1 sum of the
    payload.

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

    if response.code != numbers.codes.CONTENT:
        return

    response.opt.etag = hashlib.sha1(response.payload).digest()[:8]
    if request.opt.etags is not None and response.opt.etag in request.opt.etags:
        response.code = numbers.codes.VALID
        response.payload = b''

class Resource(interfaces.Resource):
    """Simple base implementation of the :class:`interfaces.Resource`
    interface

    The render method delegates content creation to ``render_$METHOD`` methods,
    and responds appropriately to unsupported methods.
    """

    @asyncio.coroutine
    def render(self, request):
        if not request.code.is_request():
            raise error.UnsupportedMethod()
        m = getattr(self, 'render_%s' % request.code, None)
        if not m:
            raise error.UnallowedMethod()
        return m(request)

class ObservableResource(Resource, interfaces.ObservableResource):
    def __init__(self):
        super(ObservableResource, self).__init__()
        self._observations = set()

    @asyncio.coroutine
    def add_observation(self, request, serverobservation):
        self._observations.add(serverobservation)
        serverobservation.accept((lambda s=self._observations, obs=serverobservation: s.remove(obs)))

    def updated_state(self):
        """Call this whenever the resource was updated, and a notification
        should be sent to observers."""

        for o in self._observations:
            o.trigger()


class Site(interfaces.ObservableResource):
    """Typical root element that gets passed to a :class:`Context` and contains
    all the resources that can be found when the endpoint gets accessed as a
    server.

    This provides easy registration of statical resources.

    Add resources at absolute locations using the :meth:`.add_observation`
    method."""

    def __init__(self):
        self._resources = {}

    @asyncio.coroutine
    def render(self, request):
        try:
            child = self._resources[request.opt.uri_path]
        except KeyError:
            raise error.NoResource()
        else:
            return child.render(request)

    @asyncio.coroutine
    def add_observation(self, request, serverobservation):
        try:
            child = self._resources[request.opt.uri_path]
        except KeyError:
            return

        try:
            yield from child.add_observation(request, serverobservation)
        except AttributeError:
            pass

    def add_resource(self, path, resource):
        self._resources[tuple(path)] = resource
