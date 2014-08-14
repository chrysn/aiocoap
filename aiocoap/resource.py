# This file is part of the Python aiocoap library project.
#
# Copyright (c) Twisted Matrix Laboratories,
#               2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

# -*- test-case-name: twisted.web.test.test_web -*-

"""
Implementation of the lowest-level Resource class.
"""

import copy
import warnings

from . import error
from itertools import chain


def get_child_for_request(resource, request):
    """
    Traverse resource tree to find who will handle the request.
    """
    while request.postpath and not resource.isLeaf:
        pathElement = request.postpath.pop(0)
        request.prepath.append(pathElement)
        resource = resource.get_child_with_default(pathElement, request)
    return resource


class CoAPResource:
    """
    CoAP-accessible resource.

    """

    #entityType = IResource

    server = None

    def __init__(self):
        """Initialize.
        """
        self.children = {}
        self.params = {}
        self.visible = False
        self.observers = {} # (address, token) -> observation

    observable = False
    observe_index = 0
    isLeaf = 0

    ### Abstract Collection Interface

    def list_static_names(self):
        return self.children.keys()

    def list_static_entities(self):
        return self.children.items()

    def list_names(self):
        return self.list_static_names() + self.list_dynamic_names()

    def list_entities(self):
        return self.list_static_entities() + self.list_dynamic_entities()

    def list_dynamic_names(self):
        return []

    def list_dynamic_entities(self, request=None):
        return []

    def get_static_entity(self, name):
        return self.children.get(name)

    def get_dynamic_entity(self, name, request):
        if name not in self.children:
            return self.get_child(name, request)
        else:
            return None

    def del_entity(self, name):
        del self.children[name]

    def really_put_entity(self, name, entity):
        self.children[name] = entity

    # Concrete HTTP interface

    def get_child(self, path, request):
        """
        Retrieve a 'child' resource from me.

        Implement this to create dynamic resource generation -- resources which
        are always available may be registered with self.put_child().

        This will not be called if the class-level variable 'isLeaf' is set in
        your subclass; instead, the 'postpath' attribute of the request will be
        left as a list of the remaining path elements.

        For example, the URL /foo/bar/baz will normally be::

          | site.resource.get_child('foo').get_child('bar').get_child('baz').

        However, if the resource returned by 'bar' has isLeaf set to true, then
        the get_child call will never be made on it.

        :param path: a string, describing the child

        :param request: a twisted.web.server.Request specifying meta-information
                        about the request that is being made for this child.
        """
        raise error.NoResource

    def get_child_with_default(self, path, request):
        """
        Retrieve a static or dynamically generated child resource from me.

        First checks if a resource was added manually by put_child, and then
        call get_child to check for dynamic resources. Only override if you want
        to affect behaviour of all child lookups, rather than just dynamic
        ones.

        This will check to see if I have a pre-registered child resource of the
        given name, and call get_child if I do not.
        """
        if path in self.children:
            return self.children[path]
        return self.get_child(path, request)

    def put_child(self, path, child):
        """
        Register a static child.

        You almost certainly don't want '/' in your path. If you
        intended to have the root of a folder, e.g. /foo/, you want
        path to be ''.
        """
        self.children[path] = child
        child.server = self.server

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

    def add_param(self, param):
        self.params.setdefault(param.name, []).append(param)

    def delete_param(self, name):
        if name in self.params:
            self.params.pop(name)

    def get_param(self, name):
        return self.params.get(name)

    def encode_params(self):
        data = [""]
        param_list = chain.from_iterable(sorted(self.params.values(), key=lambda x: x[0].name))
        for param in param_list:
            data.append(param.encode())
        return (';'.join(data))

    def generate_resource_list(self, data, path=""):
        params = self.encode_params() + (";obs" if self.observable else "")
        if self.visible is True:
            if path is "":
                data.append('</>' + params)
            else:
                data.append('<' + path + '>' + params)
        for key in self.children:
            self.children[key].generate_resource_list(data, path + "/" + key)

    def updated_state(self):
        """Call this whenever the resource was updated, and a notification
        should be sent to observers."""

        # this implements the second implementation suggestion from
        # draft-ietf-coap-observe-11 section 4.4
        #
        ## @TODO handle situations in which this gets called more often than
        #        2^32 times in 256 seconds (or document why we can be sure that
        #        that will not happen)
        self.observe_index = (self.observe_index + 1) % (2**24)

        for o in self.observers.values():
            o.trigger()


class LinkParam(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def decode(self, rawdata):
        pass

    def encode(self):
        return '%s="%s"' % (self.name, self.value)


class Site():
    """Root element that gets passed to a :class:`Context` and contains
    all the resources that can be found when the endpoint gets accessed as a
    server."""

    def __init__(self, root_resource):
        self.resource = root_resource

    def get_resource_for(self, request):
        """
        Get a resource for a request.

        This iterates through the resource heirarchy, calling
        get_child_with_default on each resource it finds for a path element,
        stopping when it hits an element where isLeaf is true.
        """
        #request.en = self
        # Sitepath is used to determine cookie names between distributed
        # servers and disconnected sites.
        request.sitepath = copy.copy(request.prepath)
        return get_child_for_request(self.resource, request)



