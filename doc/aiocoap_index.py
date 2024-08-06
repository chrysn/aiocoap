# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

import functools
import re
import os
import textwrap
import glob
import os.path

from docutils.parsers.rst.directives.misc import Include

rtd_re = re.compile(
    "^\\.\\. _([^:]+): http://aiocoap.readthedocs.io/en/latest/(.*)\\.html$"
)
filelink_re = re.compile("^\\.\\. _([^:]+): ([^:]+)$")


def addrepl(replacements, pattern, prefix, linkbody):
    """Given details of a sphinx-ified link, place an entry in the replacements
    dictionary that is suitable for full-text substitution later on"""
    pretty = pattern.strip("`")
    if pretty != linkbody:
        sphinxlink = ":%s:`%s <%s>`" % (prefix, pretty, linkbody)
    else:
        sphinxlink = ":%s:`%s`" % (prefix, linkbody)
    replacements[pattern + "_"] = sphinxlink


def modified_insert_input(include_lines, path, original=None):
    """A filter for the insert_input function that preprocesses the input in
    the following ways:

    * Remove all external hyperlink targets to readthedocs (and guess the way
      this link needs to be expressed in Sphinx)
    * Remove all local (relative) link targets
    * Replace words referencing them with the appropriate Sphinx reference"""
    new_lines = []
    replacements = {}
    for line in include_lines:
        rtd_match = rtd_re.match(line)
        filelink_match = filelink_re.match(line)
        if rtd_match:
            pattern, linkbody = rtd_match.groups()
            prefix = "doc"
            addrepl(replacements, pattern, prefix, linkbody)
        elif filelink_match:
            # for things like LICENSE
            pattern, linkbody = filelink_match.groups()
            addrepl(replacements, pattern, "doc", linkbody)
        else:
            # only keep lines that are still relevant (that's most lines)
            new_lines.append(line)
    new_lines = [
        functools.reduce(lambda s, rep: s.replace(*rep), replacements.items(), x)
        for x in new_lines
    ]
    original(new_lines, path)


class IncludePreprocessed(Include):
    """Include a file (like the 'Include' directive), but preprocess its input
    as described in modified_insert_input."""

    def run(self):
        self.state_machine.insert_input = functools.partial(
            modified_insert_input, original=self.state_machine.insert_input
        )
        try:
            result = super().run()
        finally:
            del self.state_machine.insert_input
        return result


def build_moduledocs(app):
    """Create per-module sources like sphinx-apidoc, but at build time and with
    customizations."""
    srcdir = app.builder.srcdir

    moddir = srcdir / "module"
    os.makedirs(moddir, exist_ok=True)

    basedir = srcdir.parent
    docs = [
        x.removesuffix(".py").replace("/", ".").replace(".__init__", "")
        for x in glob.glob("aiocoap/**/*.py", recursive=True, root_dir=basedir)
    ]

    for x in docs:
        commonstart = textwrap.dedent(f"""\
            {x} module
            ====================================================================================
            """)

        if x in ("aiocoap.numbers", "aiocoap.transports"):
            # They have explicit intros pointing out submodules and/or
            # describing any reexports
            text = commonstart + textwrap.dedent(f"""
                .. automodule:: {x}
                .. toctree::
                    :glob:

                    {x}.*
                """)
        elif x in ("aiocoap",):
            # They have explicit intros listing submodules
            text = commonstart + textwrap.dedent(f"""
                .. automodule:: {x}
                """)
        elif x.startswith("aiocoap.cli."):
            if x in ("aiocoap.cli.defaults", "aiocoap.cli.common"):
                # These neither have a man page, nor do they go into the documentation
                continue
            executablename = "aiocoap-" + x.removeprefix("aiocoap.cli.")
            # no ".. automodule:: {x}" because the doc string is already used
            # by the argparse, and thus would be repeated
            text = textwrap.dedent(f"""
                    {executablename}
                    ==============================

                    .. argparse::
                        :ref: {x}.build_parser
                        :prog: {executablename}

                    """)
        else:
            text = commonstart + textwrap.dedent(f"""
                .. automodule:: {x}
                    :members:
                    :undoc-members:
                    :show-inheritance:
                """)
        docname = f"{moddir}/{x}.rst"

        if os.path.exists(docname) and open(docname).read() == text:
            continue
        else:
            with open(moddir / (x + ".rst"), "w") as outfile:
                outfile.write(text)

    for f in os.listdir(moddir):
        if f.endswith(".rst") and f.removesuffix(".rst") not in docs:
            os.unlink(moddir + "/" + f)


def setup(app):
    """Sphinx extension that builds the aiocoap index page from a non-sphinx
    and thus github-suitable ReST file, and also creates sphinx-apidoc style
    per-module pages customized to what I'd like to see there"""

    app.add_directive("include_preprocessed", IncludePreprocessed)
    app.connect("builder-inited", build_moduledocs)
