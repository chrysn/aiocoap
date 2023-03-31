# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""This module contains in-place modifications to the LinkHeader module to
satisfy RFC6690 constraints.

It is a general nursery for what aiocoap needs of link-format management before
any of this is split out into its own package.
"""

from .vendored import link_header

class LinkFormat(link_header.LinkHeader):
    def __str__(self):
        return ','.join(str(link) for link in self.links)

class Link(link_header.Link):
    # This is copy-pasted from the link_header module's code, just replacing
    # the '; ' with ';'.
    #
    # Original copyright Michael Burrows <mjb@asplake.co.uk>, distributed under
    # the BSD license
    def __str__(self):
        def str_pair(key, value):
            if value is None:
                return key
# workaround to accomodate copper
#            elif RE_ONLY_TOKEN.match(value) or key.endswith('*'):
#                return '%s=%s' % (key, value)
            else:
                return '%s="%s"' % (key, value.replace('"', r'\"'))
        return ';'.join(['<%s>' % self.href] +
                         [str_pair(key, value)
                          for key, value in self.attr_pairs])

def parse(linkformat):
    data = link_header.parse(linkformat)
    data.__class__ = LinkFormat
    for l in data.links:
        l.__class__ = Link
    return data
