# -*- test-case-name: twisted.web.test.test_web -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Implementation of the lowest-level Resource class.
"""

import copy
import warnings

from zope.interface import Attribute, implements, Interface

import iot.error
import iot.coap as coap
from itertools import chain
from twisted.python import log
from twisted.python.reflect import prefixedMethodNames
from twisted.web.resource import IResource


def getChildForRequest(resource, request):
    """
    Traverse resource tree to find who will handle the request.
    """
    while request.postpath and not resource.isLeaf:
        pathElement = request.postpath.pop(0)
        request.prepath.append(pathElement)
        resource = resource.getChildWithDefault(pathElement, request)
    return resource


class CoAPResource:
    """
    CoAP-accessible resource.

    I serve 2 main purposes; one is to provide a standard representation for
    what CoAP specification calls an 'entity', and the other is to provide an
    abstract directory structure for URL retrieval.
    """

    implements(IResource)

    #entityType = IResource

    server = None

    def __init__(self):
        """Initialize.
        """
        self.children = {}
        self.params = {}
        self.visible = False

    isLeaf = 0

    ### Abstract Collection Interface

    def listStaticNames(self):
        return self.children.keys()

    def listStaticEntities(self):
        return self.children.items()

    def listNames(self):
        return self.listStaticNames() + self.listDynamicNames()

    def listEntities(self):
        return self.listStaticEntities() + self.listDynamicEntities()

    def listDynamicNames(self):
        return []

    def listDynamicEntities(self, request=None):
        return []

    def getStaticEntity(self, name):
        return self.children.get(name)

    def getDynamicEntity(self, name, request):
        if name not in self.children:
            return self.getChild(name, request)
        else:
            return None

    def delEntity(self, name):
        del self.children[name]

    def reallyPutEntity(self, name, entity):
        self.children[name] = entity

    # Concrete HTTP interface

    def getChild(self, path, request):
        """
        Retrieve a 'child' resource from me.

        Implement this to create dynamic resource generation -- resources which
        are always available may be registered with self.putChild().

        This will not be called if the class-level variable 'isLeaf' is set in
        your subclass; instead, the 'postpath' attribute of the request will be
        left as a list of the remaining path elements.

        For example, the URL /foo/bar/baz will normally be::

          | site.resource.getChild('foo').getChild('bar').getChild('baz').

        However, if the resource returned by 'bar' has isLeaf set to true, then
        the getChild call will never be made on it.

        @param path: a string, describing the child

        @param request: a twisted.web.server.Request specifying meta-information
                        about the request that is being made for this child.
        """
        raise iot.error.NoResource

    def getChildWithDefault(self, path, request):
        """
        Retrieve a static or dynamically generated child resource from me.

        First checks if a resource was added manually by putChild, and then
        call getChild to check for dynamic resources. Only override if you want
        to affect behaviour of all child lookups, rather than just dynamic
        ones.

        This will check to see if I have a pre-registered child resource of the
        given name, and call getChild if I do not.
        """
        if path in self.children:
            return self.children[path]
        return self.getChild(path, request)

    def putChild(self, path, child):
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
        if request.code not in coap.requests:
            raise iot.error.UnsupportedMethod()
        m = getattr(self, 'render_' + coap.requests[request.code], None)
        if not m:
            raise iot.error.UnallowedMethod()
        return m(request)

    def addParam(self, param):
        self.params.setdefault(param.name, []).append(param)

    def deleteParam(self, name):
        if name in self.params:
            self.params.pop(name)

    def getParam(self, name):
        return self.params.get(name)

    def encode_params(self):
        data = [""]
        param_list = chain.from_iterable(sorted(self.params.values(), key=lambda x: x[0].name))
        for param in param_list:
            data.append(param.encode())
        return (';'.join(data))

    def generateResourceList(self, data, path=""):
        if self.visible is True:
            if path is "":
                data.append('</>' + self.encode_params())
            else:
                data.append('<' + path + '>' + self.encode_params())
        for key in self.children:
            self.children[key].generateResourceList(data, path + "/" + key)


class LinkParam(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value

    def decode(self, rawdata):
        pass

    def encode(self):
        return '%s="%s"' % (self.name, self.value)

__all__ = [
    'IResource', 'getChildForRequest', 'Resource', 'LinkParam']


class Endpoint():

    counter = 0

    def __init__(self, root_resource):
        """
        Initialize endpoint.
        """
        self.resource = root_resource

    def render(self, request):
        """
        Redirect because a Site is always a directory.
        """
        request.redirect(request.prePathURL() + '/')
        #TODO: check this finish method
        request.finish()

    def getChildWithDefault(self, pathEl, request):
        """
        Emulate a resource's getChild method.
        """
        request.site = self
        return self.resource.getChildWithDefault(pathEl, request)

    def getResourceFor(self, request):
        """
        Get a resource for a request.

        This iterates through the resource heirarchy, calling
        getChildWithDefault on each resource it finds for a path element,
        stopping when it hits an element where isLeaf is true.
        """
        #request.en = self
        # Sitepath is used to determine cookie names between distributed
        # servers and disconnected sites.
        request.sitepath = copy.copy(request.prepath)
        return getChildForRequest(self.resource, request)



