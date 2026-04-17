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
    """Variation of the now vendered-in link_header package.

    This accounts for the RFC6690 constraint (not present in RFC5899) that
    there be no space after commas or semicolons.

    >>> str(LinkFormat([Link("/parent/", rel="up"), Link("/parent/here/child")]))
    '</parent/>;rel="up",</parent/here/child>'
    """

    def __str__(self):
        return ",".join(str(link) for link in self.links)


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
            # workaround to accommodate copper
            #            elif RE_ONLY_TOKEN.match(value) or key.endswith('*'):
            #                return '%s=%s' % (key, value)
            else:
                return '%s="%s"' % (key, value.replace('"', r"\""))

        return ";".join(
            ["<%s>" % self.href]
            + [str_pair(key, value) for key, value in self.attr_pairs]
        )


def parse(linkformat: str | bytes) -> LinkFormat:
    """Parses RFC6690 links.

    Unlike the (now vendored-in) link_header package's parsing, this

    - accepts either bytes or strings; the former are decoded as UTF-8
    - produces types that, in their serialization, account for differences between RFC6690 and RFC5899

    >>> parse(b"</hell\\xc3\\xb6>")
    LinkHeader([Link('/hellö')])
    >>> parse("</hellö>")
    LinkHeader([Link('/hellö')])
    """
    if isinstance(linkformat, bytes):
        linkformat = linkformat.decode("utf-8")
    data = link_header.parse(linkformat)
    data.__class__ = LinkFormat
    for link in data.links:
        link.__class__ = Link
    return data
