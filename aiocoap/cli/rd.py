# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

"""A plain CoAP resource directory according to
draft-ietf-core-resource-directory-25

Known Caveats:

    * This may and will make exotic choices about discoverable paths whereever
      it can (see StandaloneResourceDirectory documentation)

    * Split-horizon is not implemented correctly

    * Unless enforced by security, endpoint and sector names
      (ep, d) are not checked for their lengths or other validity.

    * Simple registrations don't cache .well-known/core contents

    * Security Policies are currently limited to a per-endpoint level. Some
      use cases might require permissions to be set on a per-resource level,
      i.e. limiting which relation types or resource types a specific endpoint
      is allowed to register (see draft-ietf-core-resource-directory-28,
      section 7.2)

Security Policies
~~~~~~~~~~~~~~~~~

The RD has support for security policies to limit access to specific endpoints
and endpoint names to pre-specified credentials (e.g. DTLS keys).

Security policies are defined in a JSON file and enabled using the
`--security-policy [SECURITY_POLICY]` command line option.

Each policy entry maps a credential reference/claim (as specified in the
credentials file, see credentials.(py|cddl)) to the permissions that clients
with these credentials should have when accessing this endpoint.

Currently, three permission bits are defined:

    * `read`  : Allows accessing the links registered for this endpoint. This
                also includes requests to the resource/endpoint lookup interface,
                i.e. if this permission is not set, links from this endpoint are
                not shown in resource/endpoint lookups.

    * `write` : Allows updating, modifying or deleting a registration.

    * `create`: Allows creating a registration for this endpoint and sector
                name combination. Setting the `write` bit also sets this bit
                implicitly, but not the other way around.

Policies can be defined on a per-sector and a per-endpoint basis. If a policy
is defined for a specific endpoint, the policies of its sector are ignored.
The sector policies therefore apply to all endpoints that **do not** have their
own policies defined, including ones that have not been created yet.

In addition to the permission bits, there is a global setting called
`registrar_has_permissions`, which is enabled by default and grants a
registrar full permissions for the registrations they themselves created, even
though they are not defined explicitly.

By enabling this setting and giving registrars just the `create` permission bit
for a specific sector (and no `write` permission), it is possible to achieve a
"first-come-first-remembered" security policy, where registrars can register
arbritrary endpoint names, while other clients may not alter a registration
after another registrar has used that name.

Policies for the default sector/no sector (if no sector is set) can be defined
using the special ":default:" sector name.
Policies that should apply to all clients even if they don't have any
credentials (default policies) can be set using the special ":default:" credential
reference/claim.

If a client has multiple claims/multiple policies apply (e.g. the default
policy and another one), the permission bits are combined/ORed.

An example of such a security policy JSON file is shown here:
```
{
    "sectors": {
    	":default:": {
    		"endpoints": {
    			"ep1": {
    				"policies": {
    					":key_1": {
    						"read": true,
    						"write": true,
    						"create": true
    					}
    				}
    			}
    		},
    		"default_policies": {
    			":key_2": {
    				"write": true,
    				"create": true
    			},
    			":default:": {
    				"read": true,
    				"write": false,
    				"create": false
    			}
    		}
    	}
    },
    "registrar_has_permissions": true
}
```

This example file will result in the following rules:

    * Registrations for other sectors than the default one (i.e. no sector) are
      not allowed.

    * Registrants possessing the credentials for the ":key_2" claim (the
      credentials need to be specified in the credentials JSON file) may create
      endpoints with arbritrary names, except for the "ep1" endpoint name.
      After these endpoints are registered, anyone with the ":key_2" claim may
      modify these registrations, because they have the sector-wide `write`
      permission.

    * Registrants possesing the credentials for the ":key_1" claim may not
      create registrations with arbritrary endpoint names, but can create
      registrations with the endpoint name "ep1".

    * The "ep1" registration is invisible to people that don't have credentials
      for the ":key_1" claim, i.e. links registered there do not appear in any
      lookups, while all other registrations are visible to all clients, even
      those that don't have any credentials.

"""

import string
import sys
import logging
import asyncio
import argparse
from urllib.parse import urljoin
import itertools
from enum import IntFlag
from pathlib import Path
import json

import aiocoap
from aiocoap.resource import Site, Resource, ObservableResource, PathCapable, WKCResource, link_format_to_message
from aiocoap.proxy.server import Proxy
from aiocoap.util.cli import AsyncCLIDaemon
import aiocoap.util.uri
from aiocoap import error
from aiocoap.cli.common import add_server_arguments, server_context_from_arguments
from aiocoap.numbers import media_types_rev
import aiocoap.proxy.server

from aiocoap.util.linkformat import Link, LinkFormat, parse

import link_header

IMMUTABLE_PARAMETERS = ('ep', 'd', 'proxy')

# Sector key in the security policy configuration whose value should be used
# for the "default" sector (i.e. if no sector is set).
# Might need to be changed if there is a situation where ":default:" is used
# as an actual sector name.
DEFAULT_SECTOR_KEY = ':default:'

# Claim/credential reference key in the policy map whose value should be
# treated as the "default" permissions for users that don't have any claims.
# Might need to be changed if there is a situation where ":default:" is used
# as an actual claim name (even though this can also be fixed by just using
# a different name, since the claim names are only used internally and
# arbritrarily set in the credentials file).
DEFAULT_CLAIM_KEY = ':default:'

def query_split(msg):
    """Split a message's query up into (key, [*value]) pairs from a
    ?key=value&key2=value2 style Uri-Query options.

    Keys without an `=` sign will have a None value, and all values are
    expressed as an (at least 1-element) list of repetitions.

    >>> m = aiocoap.Message(uri="coap://example.com/foo?k1=v1.1&k1=v1.2&obs")
    >>> query_split(m)
    {'k1': ['v1.1', 'v1.2'], 'obs': [None]}
    """
    result = {}
    for q in msg.opt.uri_query:
        if '=' not in q:
            k = q
            # matching the representation in link_header
            v = None
        else:
            k, v = q.split('=', 1)
        result.setdefault(k, []).append(v)
    return result

def pop_single_arg(query, name):
    """Out of query which is the output of query_split, pick the single value
    at the key name, raise a suitable BadRequest on error, or return None if
    nothing is there. The value is removed from the query dictionary."""

    if name not in query:
        return None
    if len(query[name]) > 1:
        raise error.BadRequest("Multiple values for %r" % name)
    return query.pop(name)[0]

def get_single_arg(query, name):
    """Out of query which is the output of query_split, pick the single value
    at the key name, raise a suitable BadRequest on error, or return None if
    nothing is there. The value remains in the query dictionary."""

    if name not in query:
        return None
    if len(query[name]) > 1:
        raise error.BadRequest("Multiple values for %r" % name)
    return query.get(name)[0]

class CommonRD:
    # "Key" here always means an (ep, d) tuple.

    entity_prefix = ("reg",)

    def __init__(self, proxy_domain=None, security_policy_data=None):
        super().__init__()

        self._by_key = {} # key -> Registration
        self._by_path = {} # path -> Registration

        self._updated_state_cb = []

        self.proxy_domain = proxy_domain
        self.proxy_active = {} # uri_host -> Remote

        self.policy = self.SecurityPolicy._policy_from_structureddata(security_policy_data)

    class SecurityPolicy:
        class Permissions(IntFlag):
            CREATE = 4
            READ = 2
            WRITE = 1 | CREATE
            NONE = 0
            ALL = CREATE | READ | WRITE

        class EndpointPolicy:
            def __init__(self, credential_policies):
                self.policies = credential_policies

        class SectorPolicy:
            def __init__(self, credential_policies, endpoints=None):
                self.endpoints = dict() if endpoints is None else endpoints
                self.policies = credential_policies

        @classmethod
        def _policy_from_structureddata(cls, data=None):

            if data is None:
                return cls(False)

            def _read_policy_entries(policy_data):
                permissions = cls.Permissions.NONE

                if policy_data.get('read', False):
                    permissions = permissions | cls.Permissions.READ

                if policy_data.get('write', False):
                    permissions = permissions | cls.Permissions.WRITE

                if policy_data.get('create', False):
                    permissions = permissions | cls.Permissions.CREATE

                return permissions

            sectors = dict()
            for sector_name, sector_data in data['sectors'].items():
                endpoints = dict()
                for endpoint_name, endpoint_data in sector_data.get('endpoints', dict()).items():
                    ep_policies = {cred_ref if cred_ref != DEFAULT_CLAIM_KEY else None: _read_policy_entries(policy_data) for cred_ref, policy_data in endpoint_data['policies'].items()}
                    endpoints[endpoint_name] = cls.EndpointPolicy(ep_policies)

                sec_policies = {cred_ref if cred_ref != DEFAULT_CLAIM_KEY else None: _read_policy_entries(policy_data) for cred_ref, policy_data in sector_data['default_policies'].items()}
                if sector_name == DEFAULT_SECTOR_KEY:
                    sector_name = None
                sectors[sector_name] = cls.SectorPolicy(sec_policies, endpoints)

            return cls(True, sectors, data.get('registrar_has_permissions', True))

        def __init__(self, enable, sectors=None, registrar_full_permissions=True):
            self.enable = enable
            self.sectors = dict() if sectors is None else sectors
            self.registrar_full_permissions = registrar_full_permissions

        def infer_ep_name(self, claims, sector_name=None):
            # Find endpoint name if none was provided (according to
            # draft-ietf-core-resource-directory, section 5).
            endpoint_name = None
            if sector_name in self.sectors:
                sector = self.sectors[sector_name]

                # Check if the client is allowed to make registrations for
                # arbritrary names, if so, we can't infer one.
                applicable_claims = set(claims).intersection(sector.policies.keys())
                for claim in applicable_claims:
                    if sector.policies[claim].permissions & self.Permissions.CREATE:
                        return None

                # Check all endpoints for which a policy exists whether they
                # have an entry for this set of credentials.
                for ep_name_iter, endpoint in sector.endpoints.items():
                    applicable_claims = set(claims).intersection(endpoint.policies.keys())
                    for claim in applicable_claims:
                        if endpoint.policies[claim].permissions & self.Permissions.CREATE:
                            # We can only infer the endpoint name if the
                            # registrant only has one possible endpoint name it
                            # can register.
                            # Otherwise, do not provide an inferred name
                            if endpoint_name is not None:
                                return None
                            # Infer endpoint name
                            endpoint_name = ep_name_iter

            return endpoint_name

        def get_permissions(self, claims, sector_name, endpoint_name, is_registrar=False):
            # If security policies are disabled, allow everything.
            if not self.enable:
                return self.Permissions.ALL

            # If the registrar of a specific endpoint should have full
            # permissions and the requester is the registrar, return full
            # permissions.
            if is_registrar and self.registrar_full_permissions:
                return self.Permissions.ALL

            # No policy for the sector exists, so there should be no access.
            if sector_name not in self.sectors:
                return self.Permissions.NONE

            claims = set(claims)
            # Default permissions that should always apply regardless of claims
            # are stored in the policy dictionary with the key "None".
            claims.add(None)

            sector = self.sectors[sector_name]

            # If no endpoint specific policy is found, default to the sector-
            # wide policy.
            policies = sector.policies

            # Check if a policy specific to the endpoint name exists, apply
            # this one instead if this is the case.
            if endpoint_name in sector.endpoints:
                policies = sector.endpoints[endpoint_name].policies


            # Take all claims for which relevant policies exist, and see which
            # ones match with the ones the client has.
            applicable_claims = claims.intersection(policies.keys())
            # Combine all permissions that someone with this set of claims
            # should have.
            permissions = self.Permissions.NONE
            for claim in applicable_claims:
                permissions = permissions | policies[claim]

            return permissions

    class Registration:
        # FIXME: split this into soft and hard grace period (where the former
        # may be 0). the node stays discoverable for the soft grace period, but
        # the registration stays alive for a (possibly much longer, at least
        # +lt) hard grace period, in which any action on the reg resource
        # reactivates it -- preventing premature reuse of the resource URI
        grace_period = 15

        @property
        def href(self):
            return '/' + '/'.join(self.path)

        def __init__(self, static_registration_parameters, path, network_remote, delete_cb, update_cb, registration_parameters, proxy_host, setproxyremote_cb):
            # note that this can not modify d and ep any more, since they are
            # already part of the key and possibly the path
            self.path = path
            self.links = LinkFormat([])

            self._delete_cb = delete_cb
            self._update_cb = update_cb

            self.registration_parameters = static_registration_parameters
            self.lt = 90000
            self.base_is_explicit = False

            self.proxy_host = proxy_host
            self._setproxyremote_cb = setproxyremote_cb

            self.registrar = network_remote

            self.update_params(network_remote, registration_parameters, is_initial=True)

        def update_params(self, network_remote, registration_parameters, is_initial=False):
            """Set the registration_parameters from the parsed query arguments,
            update any effects of them, and and trigger any observation
            observation updates if requried (the typical ones don't because
            their registration_parameters are {} and all it does is restart the
            lifetime counter)"""

            if any(k in ('ep', 'd') for k in registration_parameters.keys()):
                # The ep and d of initial registrations are already popped out
                raise error.BadRequest("Parameters 'd' and 'ep' can not be updated")

            # Not in use class "R" or otherwise conflict with common parameters
            if any(k in ('page', 'count', 'rt', 'href', 'anchor') for k in
                    registration_parameters.keys()):
                raise error.BadRequest("Unsuitable parameter for registration")

            if (is_initial or not self.base_is_explicit) and 'base' not in \
                    registration_parameters:
                # check early for validity to avoid side effects of requests
                # answered with 4.xx
                if self.proxy_host is None:
                    try:
                        network_base = network_remote.uri
                    except error.AnonymousHost:
                        raise error.BadRequest("explicit base required")
                else:
                    # FIXME: Advertise alternative transports (write alternative-transports)
                    network_base = 'coap://' + self.proxy_host

            if is_initial:
                # technically might be a re-registration, but we can't catch that at this point
                actual_change = True
            else:
                actual_change = False

            # Don't act while still checking
            set_lt = None
            set_base = None

            if 'lt' in registration_parameters:
                try:
                    set_lt = int(pop_single_arg(registration_parameters, 'lt'))
                except ValueError:
                    raise error.BadRequest("lt must be numeric")

            if 'base' in registration_parameters:
                set_base = pop_single_arg(registration_parameters, 'base')

            if set_lt is not None and self.lt != set_lt:
                actual_change = True
                self.lt = set_lt
            if set_base is not None and (is_initial or self.base != set_base):
                actual_change = True
                self.base = set_base
                self.base_is_explicit = True

            if not self.base_is_explicit and (is_initial or self.base != network_base):
                self.base = network_base
                actual_change = True

            if any(v != self.registration_parameters.get(k) for (k, v) in registration_parameters.items()):
                self.registration_parameters.update(registration_parameters)
                actual_change = True

            if is_initial:
                self._set_timeout()
            else:
                self.refresh_timeout()

            if actual_change:
                self._update_cb()

            if self.proxy_host:
                self._setproxyremote_cb(network_remote)

        def delete(self):
            self.timeout.cancel()
            self._update_cb()
            self._delete_cb()

        def _set_timeout(self):
            delay = self.lt + self.grace_period
            # workaround for python issue20493

            async def longwait(delay, callback):
                await asyncio.sleep(delay)
                callback()
            self.timeout = asyncio.create_task(longwait(delay, self.delete))

        def refresh_timeout(self):
            self.timeout.cancel()
            self._set_timeout()

        def get_host_link(self):
            attr_pairs = []
            for (k, values) in self.registration_parameters.items():
                for v in values:
                    attr_pairs.append([k, v])
            return Link(href=self.href, attr_pairs=attr_pairs, base=self.base, rt="core.rd-ep")

        def get_based_links(self):
            """Produce a LinkFormat object that represents all statements in
            the registration, resolved to the registration's base (and thus
            suitable for comparing anchors)."""
            result = []
            for l in self.links.links:
                href = urljoin(self.base, l.href)
                if 'anchor' in l:
                    absanchor = urljoin(self.base, l.anchor)
                    data = [(k, v) for (k, v) in l.attr_pairs if k != 'anchor'] + [['anchor', absanchor]]
                else:
                    data = l.attr_pairs + [['anchor', urljoin(href, '/')]]
                result.append(Link(href, data))
            return LinkFormat(result)

        @property
        def ep(self):
            return self.registration_parameters['ep'][0]

        @property
        def d(self):
            return self.registration_parameters.get('d', [None])[0]

    async def shutdown(self):
        pass

    def register_change_callback(self, callback):
        """Ask RD to invoke the callback whenever any of the RD state
        changed"""
        # This has no unregister equivalent as it's only called by the lookup
        # resources that are expected to be live for the remainder of the
        # program, like the Registry is.
        self._updated_state_cb.append(callback)

    def _updated_state(self):
        for cb in self._updated_state_cb:
            cb()

    def _new_pathtail(self):
        for i in itertools.count(1):
            # In the spirit of making legal but unconvential choices (see
            # StandaloneResourceDirectory documentation): Whoever strips or
            # ignores trailing slashes shall have a hard time keeping
            # registrations alive.
            path = (str(i), '')
            if path not in self._by_path:
                return path

    def initialize_endpoint(self, network_remote, registration_parameters):
        # copying around for later use in static, but not checking again
        # because reading them from the original will already have screamed by
        # the time this is used
        static_registration_parameters = {k: v for (k, v) in registration_parameters.items() if k in IMMUTABLE_PARAMETERS}

        ep = pop_single_arg(registration_parameters, 'ep')
        if ep is None:
            raise error.BadRequest("ep argument missing")
        d = pop_single_arg(registration_parameters, 'd')

        proxy = pop_single_arg(registration_parameters, 'proxy')

        if proxy is not None and proxy != 'on':
            raise error.BadRequest("Unsupported proxy value")

        key = (ep, d)

        if static_registration_parameters.pop('proxy', None):
            # FIXME: 'ondemand' is done unconditionally

            if not self.proxy_domain:
                raise error.BadRequest("Proxying not enabled")

            def is_usable(s):
                # Host names per RFC1123 (which is stricter than what RFC3986 would allow).
                #
                # Only supporting lowercase names as to avoid ambiguities due
                # to hostname capitalizatio normalization (otherwise it'd need
                # to be first-registered-first-served)
                return s and all(x in string.ascii_lowercase + string.digits + '-' for x in s)
            if not is_usable(ep) or (d is not None and not is_usable(d)):
                raise error.BadRequest("Proxying only supported for limited ep and d set (lowercase, digits, dash)")

            proxy_host = ep
            if d is not None:
                proxy_host += '.' + d
            proxy_host = proxy_host + '.' + self.proxy_domain
        else:
            proxy_host = None

        # No more errors should fly out from below here, as side effects start now

        try:
            oldreg = self._by_key[key]
        except KeyError:
            path = self._new_pathtail()
        else:
            path = oldreg.path[len(self.entity_prefix):]
            oldreg.delete()

        # this was the brutal way towards idempotency (delete and re-create).
        # if any actions based on that are implemented here, they have yet to
        # decide wheter they'll treat idempotent recreations like deletions or
        # just ignore them unless something otherwise unchangeable (ep, d)
        # changes.

        def delete():
            del self._by_path[path]
            del self._by_key[key]
            self.proxy_active.pop(proxy_host, None)

        def setproxyremote(remote):
            self.proxy_active[proxy_host] = remote

        reg = self.Registration(static_registration_parameters, self.entity_prefix + path, network_remote, delete,
                self._updated_state, registration_parameters, proxy_host, setproxyremote)

        self._by_key[key] = reg
        self._by_path[path] = reg

        return reg

    def get_endpoints(self):
        return self._by_key.values()

def link_format_from_message(message):
    """Convert a response message into a LinkFormat object

    This expects an explicit media type set on the response (or was explicitly requested)
    """
    certain_format = message.opt.content_format
    if certain_format is None:
        certain_format = message.request.opt.accept
    try:
        if certain_format == media_types_rev['application/link-format']:
            return parse(message.payload.decode('utf8'))
        elif certain_format == media_types_rev['application/link-format+json']:
            return LinkFormat.from_json_string(message.payload.decode('utf8'))
        elif certain_format == media_types_rev['application/link-format+cbor']:
            return LinkFormat.from_cbor_bytes(message.payload)
        else:
            raise error.UnsupportedMediaType()
    except (UnicodeDecodeError, link_header.ParseException):
        raise error.BadRequest()

class ThingWithCommonRD:
    def __init__(self, common_rd):
        super().__init__()
        self.common_rd = common_rd

        if isinstance(self, ObservableResource):
            self.common_rd.register_change_callback(self.updated_state)

class RegistrationCreationResourceBase(ThingWithCommonRD):

    def _prepare_creation(self, request):
        registration_parameters = query_split(request)

        claims = set(request.remote.authenticated_claims)

        ep_name = get_single_arg(registration_parameters, 'ep')
        sector_name = get_single_arg(registration_parameters, 'd')

        # Try to infer an endpoint name from the security policy if none was
        # set. If this isn't possible, we will err later (either when checking
        # permissions with an Unauthorized error or when calling
        # initialize_endpoint with a BadRequest, giving more information about
        # what could be wrong than just responding with BadRequest here)
        if ep_name is None:
            ep_name = self.common_rd.policy.infer_ep_name(claims, sector_name=sector_name)
            if ep_name is not None:
                registration_parameters['ep'].append(ep_name)

        permissions = self.common_rd.policy.get_permissions(claims, sector_name=sector_name, endpoint_name=ep_name)

        if not permissions & CommonRD.SecurityPolicy.Permissions.CREATE:
            raise error.Unauthorized("Operation not allowed due to security policy")

        return registration_parameters


class DirectoryResource(RegistrationCreationResourceBase, ThingWithCommonRD, Resource):
    ct = link_format_to_message.supported_ct
    rt = "core.rd"

    #: Issue a custom warning when registrations come in via this interface
    registration_warning = None

    async def render_post(self, request):
        links = link_format_from_message(request)

        registration_parameters = self._prepare_creation(request)

        if self.registration_warning:
            # Conveniently placed so it could be changed to something setting
            # additional registration_parameters instead
            logging.warning("Warning from registration: %s", self.registration_warning)

        regresource = self.common_rd.initialize_endpoint(request.remote, registration_parameters)
        regresource.links = links

        return aiocoap.Message(code=aiocoap.CREATED, location_path=regresource.path)

class RegistrationResource(ThingWithCommonRD, Resource):
    """The resource object wrapping a registration is just a very thin and
    ephemeral object; all those methods could just as well be added to
    Registration with `s/self.reg/self/g`, making RegistrationResource(reg) =
    reg (or handleded in a single RegistrationDispatchSite), but this is kept
    here for better separation of model and interface."""

    def __init__(self, common_rd, registration):
        super().__init__(common_rd)
        self.reg = registration

    def _get_permissions(self, request):
        is_registrar = type(request.remote) is type(self.reg.registrar) and request.remote == self.reg.registrar
        return self.common_rd.policy.get_permissions(request.remote.authenticated_claims,
                sector_name=self.reg.d,
                endpoint_name=self.reg.ep,
                is_registrar=is_registrar
        )

    async def render_get(self, request):
        if not self._get_permissions(request) & CommonRD.SecurityPolicy.Permissions.READ:
            raise error.Unauthorized("Operation not allowed due to security policy")

        return link_format_to_message(request, self.reg.links)

    def _update_params(self, msg):
        query = query_split(msg)
        self.reg.update_params(msg.remote, query)


    async def render_post(self, request):
        if not self._get_permissions(request) & CommonRD.SecurityPolicy.Permissions.WRITE:
            raise error.Unauthorized("Operation not allowed due to security policy")

        self._update_params(request)

        if request.opt.content_format is not None or request.payload:
            raise error.BadRequest("Registration update with body not specified")

        return aiocoap.Message(code=aiocoap.CHANGED)

    async def render_put(self, request):
        if not self._get_permissions(request) & CommonRD.SecurityPolicy.Permissions.WRITE:
            raise error.Unauthorized("Operation not allowed due to security policy")

        # this is not mentioned in the current spec, but seems to make sense
        links = link_format_from_message(request)

        self._update_params(request)
        self.reg.links = links

        return aiocoap.Message(code=aiocoap.CHANGED)

    async def render_delete(self, request):
        if not self._get_permissions(request) & CommonRD.SecurityPolicy.Permissions.WRITE:
            raise error.Unauthorized("Operation not allowed due to security policy")

        self.reg.delete()

        return aiocoap.Message(code=aiocoap.DELETED)

class RegistrationDispatchSite(ThingWithCommonRD, Resource, PathCapable):
    async def render(self, request):
        try:
            entity = self.common_rd._by_path[request.opt.uri_path]
        except KeyError:
            raise error.NotFound

        entity = RegistrationResource(self.common_rd, entity)

        return await entity.render(request.copy(uri_path=()))

def _paginate(candidates, query):
    page = pop_single_arg(query, 'page')
    count = pop_single_arg(query, 'count')

    try:
        candidates = list(candidates)
        if page is not None:
            candidates = candidates[int(page) * int(count):]
        if count is not None:
            candidates = candidates[:int(count)]
    except (KeyError, ValueError):
        raise error.BadRequest("page requires count, and both must be ints")

    return candidates

def _link_matches(link, key, condition):
    return any(k == key and condition(v) for (k, v) in link.attr_pairs)

class EndpointLookupInterface(ThingWithCommonRD, ObservableResource):
    ct = link_format_to_message.supported_ct
    rt = "core.rd-lookup-ep"

    async def render_get(self, request):
        query = query_split(request)

        candidates = self.common_rd.get_endpoints()

        candidates = (c for c in candidates if
                self.common_rd.policy.get_permissions(
                    request.remote.authenticated_claims,
                    sector_name=c.d,
                    endpoint_name=c.ep,
                ) & CommonRD.SecurityPolicy.Permissions.READ)

        for search_key, search_values in query.items():
            if search_key in ('page', 'count'):
                continue # filtered last

            for search_value in search_values:
                if search_value is not None and search_value.endswith('*'):
                    matches = lambda x, start=search_value[:-1]: x.startswith(start)
                else:
                    matches = lambda x: x == search_value

                if search_key in ('if', 'rt'):
                    matches = lambda x, original_matches=matches: any(original_matches(v) for v in x.split())

                if search_key == 'href':
                    candidates = (c for c in candidates if
                            matches(c.href) or
                            any(matches(r.href) for r in c.get_based_links().links)
                            )
                    continue

                candidates = (c for c in candidates if
                        (search_key in c.registration_parameters and any(matches(x) for x in c.registration_parameters[search_key])) or
                        any(_link_matches(r, search_key, matches) for r in c.get_based_links().links)
                        )

        candidates = _paginate(candidates, query)

        result = [c.get_host_link() for c in candidates]

        return link_format_to_message(request, LinkFormat(result))

class ResourceLookupInterface(ThingWithCommonRD, ObservableResource):
    ct = link_format_to_message.supported_ct
    rt = "core.rd-lookup-res"

    async def render_get(self, request):
        query = query_split(request)

        eps = self.common_rd.get_endpoints()
        eps = (ep for ep in eps if
                self.common_rd.policy.get_permissions(
                    request.remote.authenticated_claims,
                    sector_name=ep.d,
                    endpoint_name=ep.ep,
                ) & CommonRD.SecurityPolicy.Permissions.READ)

        candidates = ((e, c) for e in eps for c in e.get_based_links().links)

        for search_key, search_values in query.items():
            if search_key in ('page', 'count'):
                continue # filtered last

            for search_value in search_values:
                if search_value is not None and search_value.endswith('*'):
                    matches = lambda x, start=search_value[:-1]: x.startswith(start)
                else:
                    matches = lambda x: x == search_value

                if search_key in ('if', 'rt'):
                    matches = lambda x, original_matches=matches: any(original_matches(v) for v in x.split())

                if search_key == 'href':
                    candidates = ((e, c) for (e, c) in candidates if
                            matches(c.href) or
                            matches(e.href) # FIXME: They SHOULD give this as relative as we do, but don't have to
                            )
                    continue

                candidates = ((e, c) for (e, c) in candidates if
                        _link_matches(c, search_key, matches) or
                        (search_key in e.registration_parameters and any(matches(x) for x in e.registration_parameters[search_key]))
                        )

        # strip endpoint
        candidates = (c for (e, c) in candidates)

        candidates = _paginate(candidates, query)

        # strip needless anchors
        candidates = [
                Link(l.href, [(k, v) for (k, v) in l.attr_pairs if k != 'anchor'])
                if dict(l.attr_pairs)['anchor'] == urljoin(l.href, '/')
                else l
                for l in candidates]

        return link_format_to_message(request, LinkFormat(candidates))

class SimpleRegistration(RegistrationCreationResourceBase, ThingWithCommonRD, Resource):
    #: Issue a custom warning when registrations come in via this interface
    registration_warning = None

    def __init__(self, common_rd, context):
        super().__init__(common_rd)
        self.context = context

    async def render_post(self, request):
        query = self._prepare_creation(request)

        if 'base' in query:
            raise error.BadRequest("base is not allowed in simple registrations")

        await self.process_request(
                network_remote=request.remote,
                registration_parameters=query,
            )

        return aiocoap.Message(code=aiocoap.CHANGED)

    async def process_request(self, network_remote, registration_parameters):
        if 'proxy' not in registration_parameters:
            try:
                network_base = network_remote.uri
            except error.AnonymousHost:
                raise error.BadRequest("explicit base required")

            fetch_address = (network_base + '/.well-known/core')
            get = aiocoap.Message(uri=fetch_address)
        else:
            # ignoring that there might be a based present, that will err later
            get = aiocoap.Message(uri_path=['.well-known', 'core'])
            get.remote = network_remote

        get.code = aiocoap.GET
        get.opt.accept = media_types_rev['application/link-format']

        # not trying to catch anything here -- the errors are most likely well renderable into the final response
        response = await self.context.request(get).response_raising
        links = link_format_from_message(response)

        if self.registration_warning:
            # Conveniently placed so it could be changed to something setting
            # additional registration_parameters instead
            logging.warning("Warning from registration: %s", self.registration_warning)
        registration = self.common_rd.initialize_endpoint(network_remote, registration_parameters)
        registration.links = links

class SimpleRegistrationWKC(WKCResource, SimpleRegistration):
    def __init__(self, listgenerator, common_rd, context):
        WKCResource.__init__(self, listgenerator)
        SimpleRegistration.__init__(self, common_rd, context)
        self.registration_warning = "via .well-known/core"

class StandaloneResourceDirectory(Proxy, Site):
    """A site that contains all function sets of the CoAP Resource Directoru

    To prevent or show ossification of example paths in the specification, all
    function set paths are configurable and default to values that are
    different from the specification (but still recognizable)."""

    rd_path = ("resourcedirectory", "")
    ep_lookup_path = ("endpoint-lookup", "")
    res_lookup_path = ("resource-lookup", "")

    def __init__(self, context, lwm2m_compat=None, **kwargs):
        if lwm2m_compat is True:
            self.rd_path = ("rd",)

        # Double inheritance: works as everything up of Proxy has the same interface
        super().__init__(outgoing_context=context)

        common_rd = CommonRD(**kwargs)

        self.add_resource([".well-known", "core"], SimpleRegistrationWKC(self.get_resources_as_linkheader, common_rd=common_rd, context=context))
        self.add_resource([".well-known", "rd"], SimpleRegistration(common_rd=common_rd, context=context))

        self.add_resource(self.rd_path, DirectoryResource(common_rd=common_rd))
        if list(self.rd_path) != ["rd"] and lwm2m_compat is None:
            second_dir_resource = DirectoryResource(common_rd=common_rd)
            second_dir_resource.registration_warning = "via unannounced /rd"
            # Hide from listing
            second_dir_resource.get_link_description = lambda *args: None
            self.add_resource(["rd"], second_dir_resource)
        self.add_resource(self.ep_lookup_path, EndpointLookupInterface(common_rd=common_rd))
        self.add_resource(self.res_lookup_path, ResourceLookupInterface(common_rd=common_rd))

        self.add_resource(common_rd.entity_prefix, RegistrationDispatchSite(common_rd=common_rd))

        self.common_rd = common_rd

    def apply_redirection(self, request):
        # Fully overriding so we don't need to set an add_redirector

        # infallible as the request only gets here if the proxy path is chosen
        actual_remote = self.common_rd.proxy_active[request.opt.uri_host]
        request.remote = actual_remote
        request.opt.uri_host = None
        return request

    async def shutdown(self):
        await self.common_rd.shutdown()

    async def render(self, request):
        # Full override switching which of the parents' behavior to choose

        if request.opt.uri_host in self.common_rd.proxy_active:
            # This is never the case if proxying is disabled.
            return await Proxy.render(self, request)
        else:
            return await Site.render(self, request)

    # See render; necessary on all functions thanks to https://github.com/chrysn/aiocoap/issues/251

    async def needs_blockwise_assembly(self, request):
        if request.opt.uri_host in self.common_rd.proxy_active:
            return await Proxy.needs_blockwise_assembly(self, request)
        else:
            return await Site.needs_blockwise_assembly(self, request)

    async def add_observation(self, request, serverobservation):
        if request.opt.uri_host in self.common_rd.proxy_active:
            return await Proxy.add_observation(self, request, serverobservation)
        else:
            return await Site.add_observation(self, request, serverobservation)

def build_parser():
    p = argparse.ArgumentParser(description=__doc__)

    add_server_arguments(p)

    return p

class Main(AsyncCLIDaemon):
    async def start(self, args=None):
        parser = build_parser()
        parser.add_argument("--proxy-domain", help="Enable the RD proxy extension. Example: `.proxy.example.net` will produce base URIs like `coap://node1.proxy.example.net/`. The names must all resolve to an address the RD is bound to.", type=str)
        parser.add_argument("--lwm2m-compat", help="Compatibility mode for LwM2M clients that can not perform some discovery steps (moving the registration resource to `/rd`)", action='store_true', default=None)
        parser.add_argument("--no-lwm2m-compat", help="Disable all compativility with LwM2M clients that can not perform some discovery steps (not even accepting registrations at `/rd` with warnings)", action='store_false', dest='lwm2m_compat')
        parser.add_argument('--security-policy', help="JSON file describing the security policy to use for the RD.", type=Path)
        options = parser.parse_args(args if args is not None else sys.argv[1:])

        # Putting in an empty site to construct the site with a context
        self.context = await server_context_from_arguments(None, options)

        security_policy_data = None
        if options.security_policy is not None:
            security_policy_data = json.load(options.security_policy.open("rb"))

        self.site = StandaloneResourceDirectory(context=self.context, proxy_domain=options.proxy_domain, lwm2m_compat=options.lwm2m_compat, security_policy_data=security_policy_data)
        self.context.serversite = self.site

    async def shutdown(self):
        await self.site.shutdown()
        await self.context.shutdown()

sync_main = Main.sync_main

if __name__ == "__main__":
    sync_main()
