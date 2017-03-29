# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Client components for registering with a resource-directory server"""

import asyncio
from urllib.parse import urljoin
import logging

import link_header

from ...message import Message
from ...numbers import GET, POST, DELETE
from ... import error

__all__ = 'Registerer'

class Registerer:
    """Implementation of the client side of the registration of a resource
    directory. Until the object is :meth:`shut down <shutdown>`, it keeps the
    registration alive. It works both for registering the own context as well
    as for registering others (taking the role of a commissioning tool).

    The :attr:`state` attribute is kept up to date with an informal
    representation of whether the registration is currently active.

    The registration does not observe the resource list of the registered host
    (yet?), so registrations are only kept alive and never updated."""

    def __init__(self, context, ep, rd, d=None, et=None, lt=86400, con=None,
            loggername='coap-rd-registerer'):
        """Use a ``context`` to register the host ``con`` (defaulting to the
        own site of the context) at a given ``rd`` (resource directory) as
        under the name ``ep``. A ``d`` (domain), ``et`` (endpoint type) and
        ``lt`` can be given."""

        self.context = context
        if ':' not in rd:
            rd = 'coap://' + rd
        self.rd = rd
        self.ep = ep
        self.d = d
        self.et = et
        self.lt = lt
        self.con = con
        self.log = logging.getLogger(loggername)

        self._set_state('discovering')

        self._current_task = asyncio.Task(self._start())

    def __repr__(self):
        return "<%s at %#x: registering %s at %s as %s (currently %s)>"%(
                type(self).__name__, id(self), self.con, self.rd, self.ep,
                self.state)

    def _set_state(self, newstate):
        self.log.debug("Entering state %s", newstate)
        self.state = newstate

    class _SilentError(Exception):
        """Raised when something went wrong during the registration process,
        but an error message was already put in the log so no further backtrace
        is needed"""

    @asyncio.coroutine
    def _obtain_registration_address(self):
        lookup_uri = urljoin(self.rd,
                '/.well-known/core?rt=core.rd')

        try:
            response = yield from self.context.request(
                    Message(code=GET, uri=lookup_uri, accept=40)
                ).response_raising
            links = link_header.parse(response.payload.decode('utf8'))
        except (UnicodeDecodeError, link_header.ParseException) as e:
            self.log.error("Error parsing the RD's self description")
            raise

        addresses = [l.get_target(lookup_uri) for l in links.links
                if 'core.rd' in " ".join(l.rt).split(" ")]
        if not addresses:
            self.log.error("No registration interface found in RD's response")
            raise _SilentError()

        if len(addresses) > 1:
            self.log.warn("More than one registration interface found," \
                    " picking the first")

        return addresses[0]

    @asyncio.coroutine
    def _obtain_link_data(self):
        """Return a message describing the data to be POSTed to the
        registration interface.

        This needs to be in :class:`Message` format, but doesn't need to have
        any particular code set yet (that gets set later anyway), so in effect,
        the response message from the con can be returned as is.
        """
        if self.con is None:
            return (yield from self.context.serversite.render(
                Message(code=GET, uri_path=('.well-known', 'core'))
                ))

        return (yield from self.context.request(
                Message(code=GET, uri=urljoin(self.con, '/.well-known/core'))
                ).response_raising)

    @asyncio.coroutine
    def _start(self):
        try:
            self.registration_address, self.initial_data = yield from asyncio.gather(
                    self._obtain_registration_address(),
                    self._obtain_link_data())
        except self._SilentError:
            self._set_state('failed')
            return
        except error.ResponseWrappingError as e:
            response = e.to_message()
            self.log.error("Error received from %s during registration" \
                    " preparation (%s %s)", response.remote, response.code,
                    response.payload)
            return
        except Exception as e:
            self.log.exception(e)
            self._set_state('failed')
            return

        initial_message = self.initial_data.copy(code=POST, uri=self.registration_address)
        query = {'ep': self.ep, 'lt': self.lt}
        if self.con:
            query['con'] = self.con
        if self.et:
            query['et'] = self.et
        if self.d:
            query['d'] = self.d
        initial_message.opt.uri_query = initial_message.opt.uri_query + \
                tuple("%s=%s"%(k, v) for (k,v) in query.items())

        try:
            response = yield from self.context.request(initial_message).response_raising
        except error.ResponseWrappingError as e:
            response = e.to_message()
            self.log.error("Sending data to the RD failed (%s %s)", response.code, response.payload)
            return
        except Exception as e:
            self.log.error("Sending data to the RD failed")
            self.log.exception(e)
            return

        # FIXME this should probably be available from the API, and consider location_query etc
        self.location = urljoin(self.registration_address, "/" + "/".join(response.opt.location_path))

        self._set_state("registered")

        self._current_task = asyncio.Task(self._renew())

    @asyncio.coroutine
    def _renew(self):
        yield from asyncio.sleep(max(self.lt - 60, 60))

        self._set_state("renewing")

        try:
            response = yield from self.context.request(
                    Message(code=POST, uri=self.location)
                    ).response_raising
        except Exception as e:
            self._set_state('failed')
            self.log.error("Renewing the registration failed")
            self.log.exception(e)
            return

        self._set_state("registered")

        self._current_task = asyncio.Task(self._renew())

    @asyncio.coroutine
    def shutdown(self):
        """Delete the registration. This will not raise any resulting error
        messages but just log them, same as any errors occurring during the
        registration will only be logged."""
        self._current_task.cancel()

        if self.state == 'failed':
            return

        try:
            yield from self.context.request(
                    Message(code=DELETE, uri=self.location)
                    ).response_raising
        except Exception as e:
            self.log.error("Error deregistering from the RD")
            self.log.exception(e)
