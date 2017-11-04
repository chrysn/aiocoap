# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""Client components for registering with a resource-directory server"""

import asyncio
from urllib.parse import urljoin, urlparse
import logging

from socket import getfqdn

import link_header

from ...message import Message
from ...numbers import GET, POST, DELETE, SERVICE_UNAVAILABLE, NOT_FOUND
from ... import error

__all__ = ['Registerer']

class Registerer:
    """Implementation of the client side of the registration of a resource
    directory. Until the object is :meth:`shut down <shutdown>`, it keeps the
    registration alive. It works both for registering the own context as well
    as for registering others (taking the role of a commissioning tool).

    The :attr:`state` attribute is kept up to date with an informal
    representation of whether the registration is currently active.

    If any step in the registration fails, the object will not retry
    indefinitely, and it will back off to earlier steps; after a limited number
    of retries after the last successful step, the object permanently enters a
    failed state. (In future extension, it might listen for external events
    that allow it to restart heuristics, like a new network interface coming
    up).

    The registration does not observe the resource list of the registered host
    (yet?), so registrations are only kept alive and never updated."""

    def __init__(self, context, rd=None, lt=86400, name_from_hostname=None,
            link_source=None, registration_parameters={},
            loggername='coap-rd-registerer'):
        """Use a ``context`` to create a registration at the Resource
        directiory at ``rd`` (defaulting to "find an RD yourself"; URIs should
        have no path component, unless the user wishes to sidestep the URI
        discovery step). It will be renewed every `lifetime` seconds.

        The registration data will be obtained by querying the context's site's
        ``.well-known/core`` resource, unless another source URI is given in
        ``link_source``, in which case this object acts as a Commissioning
        Tool.

        Parameters to pass with the registration can be given in
        ``registration_parameters``. ``lt`` and ``con`` default to the
        constructor arguments ``lt`` and ``link_source``, respectively.

        If ``name_from_hostname`` is True (or by default if ``ep`` is not
        present in ``registration_parameters``), the ``ep`` and ``d``
        registration parameters are derived from the host name."""

        self._context = context

        self._link_source = None
        self._link_data = None #: Message
        self._lt = lt
        self._initial_rd = rd

        self._directory_resource = None
        self._registration_resource = None

        self._registration_parameters = dict(registration_parameters)

        if name_from_hostname or (name_from_hostname is None and
                'ep' not in registration_parameters):
            ep, _, d = getfqdn().partition('.')
            self._registration_parameters['ep'] = ep
            if d:
                self._registration_parameters['d'] = d

        self.log = logging.getLogger(loggername)

        self._task = asyncio.Task(self._run())

    def __repr__(self):
        return "<%s at %#x: registering at %s as %s (currently %s)>"%(
                type(self).__name__, id(self), self._registration_resource or
                self._directory_resource, self._registration_parameters,
                self.state)

    def _set_state(self, newstate):
        self.log.debug("Entering state %s", newstate)
        self.state = newstate

    @asyncio.coroutine
    def _fill_directory_resource(self, blacklist=set()):
        # FIXME: this should at some point catch network errors (short of
        # falling back to "RD discovery failed, backing off"), but that needs
        # falling back to other discovery methods here, and i don't know how
        # this will be done yet

        if self._directory_resource is not None:
            return

        if self._initial_rd is None:
            # FIXME: can't access DHCP options generically, dunno about SLAAC.
            # It seems to be a sane assumption that the best thing to do is to
            # assume we're on a big host and multicast is cheap here.
            self._directory_resource = yield from self._discovery_directory_uri('coap://[ff05::fd]]', blacklist=blacklist)

        components = urlparse(self._initial_rd)
        if components.path:
            if self._initial_rd in blacklist:
                raise self._UnrecoverableError("Explicitly configured RD was blacklisted")
            else:
                self._directory_resource = self._initial_rd
        else:
            self._directory_resource = yield from self._discovery_directory_uri(self._initial_rd, blacklist=blacklist)

    @asyncio.coroutine
    def _discovery_directory_uri(self, host, blacklist=set()):
        lookup_uri = urljoin(host,
                '/.well-known/core?rt=core.rd')

        try:
            # FIXME: this should be able to deal with multicasts
            response = yield from self._context.request(
                    Message(code=GET, uri=lookup_uri, accept=40)
                ).response_raising
            links = link_header.parse(response.payload.decode('utf8'))
        except (UnicodeDecodeError, link_header.ParseException) as e:
            self.log.error("Error parsing the RD's self description")
            raise

        addresses = [l.get_target(response.get_request_uri())
                for l in links.links
                if 'core.rd' in " ".join(l.rt).split(" ")]
        unfiltered_addresses = len(addresses)
        addresses = [a for a in addresses if a not in blacklist]
        if not addresses:
            if len(addresses) != unfiltered_addresses:
                raise self._UnrecoverableError("All discovered Directory Resources are blacklisted")
            else:
                raise self._UnrecoverableError("No registration interface found in RD's response")

        if len(addresses) > 1:
            self.log.warn("More than one registration interface found," \
                    " picking the first")

        return addresses[0]

    @asyncio.coroutine
    def _obtain_link_data(self):
        """Store a message describing the data to be POSTed to the
        registration interface.

        This needs to be in :class:`Message` format, but doesn't need to have
        any particular code set yet (that gets set later anyway), so in effect,
        the response message from the con can be returned as is.
        """

        if self._link_source is None:
            self._link_data = yield from self._context.serversite.render(
                Message(code=GET, uri_path=('.well-known', 'core'))
                )

        else:
            self._link_data = yield from self._context.request(
                    Message(code=GET, uri=urljoin(self._link_source, '/.well-known/core'))
                    ).response_raising

    class _RetryableError(RuntimeError):
        """Raised when an initial registration or update rails in a way that
        warrants rediscovery of the RD"""

    class _UnrecoverableError(RuntimeError):
        """Raised when the RD registration process runs out of options
        (typically with a descriptive message)"""

    @asyncio.coroutine
    def _request_with_retries(self, message):
        # FIXME: response_nonraising gives 5.00 now, but for debugging we might
        # want to show something better, and for URI discovery, we should not
        # consider this a final error
        response = yield from self._context.request(message).response_nonraising

        unavailable_retries = 0
        while response.code == SERVICE_UNAVAILABLE and response.opt.max_age is not None:
            if unavailable_retries > 6:
                raise self._RetryableError("RD responded with Service Unavailable too often")
            self.log.info("RD asked to retry the operation later")
            yield from asyncio.sleep(max(response.opt.max_age, 2**(unavailable_retries)))
            response = yield from self._context.request(message).response_nonraising

        return response

    @asyncio.coroutine
    def _register(self):
        initial_message = self._link_data.copy(code=POST, uri=self._directory_resource)
        base_query = {}
        if self._lt != 86400:
            base_query['lt'] = str(self._lt)
        if self._link_source is not None:
            base_query['con'] = self._link_source
        query = dict(base_query, **self._registration_parameters)

        initial_message.opt.uri_query = initial_message.opt.uri_query + \
                tuple("%s=%s"%(k, v) for (k,v) in query.items())

        response = yield from self._request_with_retries(initial_message)

        if not response.code.is_successful():
            raise self._RetryableError("RD responded with odd error: %s / %r"%(response.code, response.payload))

        if not response.opt.location_path:
            raise self._RetryableError("RD responded without a location")

        # FIXME this should probably be available from the API, and consider location_query etc
        self._registration_resource = urljoin(response.get_request_uri(), "/" + "/".join(response.opt.location_path))

    @asyncio.coroutine
    def _renew_registration(self):
        update_message = Message(code=POST, uri=self._registration_resource)

        response = yield from self._request_with_retries(update_message)

        if response.code == NOT_FOUND:
            raise self._RetryableError("RD forgot about the registration")

        if not response.code.is_successful():
            raise self._RetryableError("RD responded with odd error: %s / %r"%(response.code, response.payload))

    @asyncio.coroutine
    def _run(self):
        obtain = asyncio.Task(self._obtain_link_data())

        try:
            registration = yield from self._run_inner(obtain)
        except asyncio.CancelledError:
            self._set_state('cancelled')
            pass
        except self._UnrecoverableError as e:
            self._set_state('failed')
            self.log.error("Aborting RD discovery: %s", e.args[0])
        except Exception as e:
            self._set_state('failed')
            self.log.error("An error occurred during RD registration, not pursuing registration any further:")
            self.log.exception(e)
        finally:
            obtain.cancel()

    def _run_inner(self, obtain):
        errors = 0
        errors_max = 5
        failed_initialization = set()
        try_reuse_discovery = False

        while True:
            if try_reuse_discovery:
                try_reuse_discovery = False
            else:
                self._set_state('discovering')

                for i in range(4):
                    if i:
                        self.log.info("Waiting to retry RD discovery")
                        yield from asyncio.sleep(2 * 3 ** (i - 1)) # arbitrary fall-off
                    yield from self._fill_directory_resource(blacklist=failed_initialization)
                    break
                else:
                    self.log.error("Giving up RD discovery")
                    break

            link_data = yield from obtain

            self._set_state("registering")

            try:
                yield from self._register()
            except self._RetryableError as e:
                errors += 1
                if errors < errors_max:
                    self.log.warning("Initial registration failed (%s), blacklisting RD URI and retrying discovery", e)
                    failed_initialization.add(self._directory_resource)
                    self._directory_resource = None
                    continue
                else:
                    self.log.error("Giving up after too many failed initial registrations")
                    break

            # registration is active, keep it that way.

            # things look good enough to forget about past bad experiences.
            # could move this to the end of the following loop if worries come
            # up of having picked a bad RD that supports registration but not
            # registration updates
            errors = 0
            failed_initialization = set()
            try_reuse_discovery = True

            while True:
                self._set_state("registered")

                # renew 60 seconds before timeout, unless that's before the 75% mark (then wait for that)
                yield from asyncio.sleep(self._lt - 60 if self._lt > 240 else self._lt * 3 // 4)

                self._set_state("renewing")

                try:
                    yield from self._renew_registration()
                except self._RetryableError as e:
                    self.log.warning("Registration update failed (%s), retrying with new registration", e)
                    break

    @asyncio.coroutine
    def shutdown(self):
        """Delete the registration. This will not raise any resulting error
        messages but just log them, same as any errors occurring during the
        registration will only be logged."""
        self._task.cancel()

        if self._registration_resource is None:
            return

        try:
            yield from self._context.request(
                    Message(code=DELETE, uri=self._registration_resource)
                    ).response_raising
        except Exception as e:
            self.log.error("Error deregistering from the RD")
            self.log.exception(e)
