# This file is part of the Python aiocoap library project.
#
# Copyright (c) Twisted Matrix Laboratories,
#               2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio

from . import error
from . import interfaces

class CoAPResource(interfaces.Resource):
    """
    CoAP-accessible resource.

    """

    @asyncio.coroutine
    def render(self, request):
        """
        Render a given resource. See L{IResource}'s render method.

        I delegate to methods of self with the form 'render_METHOD'
        where METHOD is the HTTP that was used to make the
        request. Examples: render_GET, render_HEAD, render_POST, and
        so on. Generally you should implement those methods instead of
        overriding this one.

        render_METHOD methods are expected to return a string which
        will be the rendered page, unless the return value is
        twisted.web.server.NOT_DONE_YET, in which case it is this
        class's responsibility to write the results to
        request.write(data), then call request.finish().

        Old code that overrides render() directly is likewise expected
        to return a string or NOT_DONE_YET.
        """
        if not request.code.is_request():
            raise error.UnsupportedMethod()
        m = getattr(self, 'render_%s' % request.code, None)
        if not m:
            raise error.UnallowedMethod()
        return m(request)

    def generate_resource_list(self, data, path=""):
        params = self.encode_params() + (";obs" if self.observable else "")
        if self.visible is True:
            if path is "":
                data.append('</>' + params)
            else:
                data.append('<' + path + '>' + params)
        for key in self.children:
            self.children[key].generate_resource_list(data, path + "/" + key)

class ObservableCoAPResource(CoAPResource, interfaces.ObservableResource):
    def __init__(self):
        super(ObservableCoAPResource, self).__init__()
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

    This provides easy registration of statical resources."""

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
        self._resources[path] = resource
