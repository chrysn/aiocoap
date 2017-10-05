import functools
import re
import os
import textwrap
import glob
import os.path

def glob35(dir, recursive=True):
    return glob.glob(dir.replace('**', '*')) + \
            glob.glob(dir.replace('**', '*/*')) + \
            glob.glob(dir.replace('**', '*/*/*')) + \
            glob.glob(dir.replace('**', '*/*/*/*')) + \
            glob.glob(dir.replace('/**', ''))

from docutils.parsers.rst.directives.misc import Include

rtd_re = re.compile("^\\.\\. _([^:]+): http://aiocoap.readthedocs.io/en/latest/(.*)\\.html$")
filelink_re = re.compile("^\\.\\. _([^:]+): ([^:]+)$")

def addrepl(replacements, pattern, prefix, linkbody):
    """Given details of a sphinx-ified link, place an entry in the replacements
    dictionary that is suitable for full-text substitution later on"""
    pretty = pattern.strip('`')
    if pretty != linkbody:
        sphinxlink = ':%s:`%s <%s>`'%(prefix, pretty, linkbody)
    else:
        sphinxlink = ':%s:`%s`'%(prefix, linkbody)
    replacements[pattern + '_'] = sphinxlink

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
            prefix = 'doc'
            addrepl(replacements, pattern, prefix, linkbody)
        elif filelink_match:
            # for things like LICENSE
            pattern, linkbody = filelink_match.groups()
            addrepl(replacements, pattern, 'doc', linkbody)
        else:
            # only keep lines that are still relevant (that's most lines)
            new_lines.append(line)
    new_lines = [functools.reduce(lambda s, rep: s.replace(*rep), replacements.items(), x) for x in new_lines]
    original(new_lines, path)

class IncludePreprocessed(Include):
    """Include a file (like the 'Include' directive), but preprocess its input
    as described in modified_insert_input."""
    def run(self):
        self.state_machine.insert_input = functools.partial(modified_insert_input, original=self.state_machine.insert_input)
        try:
            result = super().run()
        finally:
            del self.state_machine.insert_input
        return result

def build_moduledocs(app):
    """Create per-module sources like sphinx-apidoc, but at build time and with
    customizations."""
    srcdir = app.builder.srcdir

    moddir = srcdir + '/module'
    os.makedirs(moddir, exist_ok=True)

    basedir = os.path.dirname(srcdir)
    docs = [x[len(basedir)+1:-3].replace('/', '.').replace('.__init__', '') for x in glob35(basedir + '/aiocoap/**/*.py', recursive=True)]

    for x in docs:
        commonstart = textwrap.dedent("""\
            {x} module
            ====================================================================================
            """).format(x=x)

        if x in ('aiocoap.numbers', 'aiocoap.transports'):
            # this does miss out on media_types{,rev}, but they're a mess
            # anyway so far
            text = commonstart + textwrap.dedent("""
                .. automodule:: {x}
                .. toctree::
                    :glob:

                    {x}.*
                """).format(x=x)
        elif x.startswith('aiocoap.cli.'):
            executablename = "aiocoap-" + x[len('aiocoap.cli.'):]
            # no ".. automodule:: {x}" because the doc string is already used
            # by the argparse, and thus would be repeated
            text = textwrap.dedent("""
                    {executablename}
                    ==============================

                    .. argparse::
                        :ref: {x}.build_parser
                        :prog: {executablename}

                    """).format(x=x, executablename=executablename)
        else:
            text = commonstart + textwrap.dedent("""
                .. automodule:: {x}
                    :members:
                    :undoc-members:
                    :show-inheritance:
                """).format(x=x)
        docname = "%s/%s.rst"%(moddir, x)

        if os.path.exists(docname) and open(docname).read() == text:
            continue
        else:
            with open(moddir + '/' + x + '.rst', 'w') as outfile:
                outfile.write(text)

    for f in os.listdir(moddir):
        if f.endswith('.rst') and f[:-4] not in docs:
            os.unlink(moddir + '/' + f)

def setup(app):
    """Sphinx extension that builds the aiocoap index page from a non-sphinx
    and thus github-suitable ReST file, and also creates sphinx-apidoc style
    per-module pages customized to what I'd like to see there"""

    app.add_directive('include_preprocessed', IncludePreprocessed)
    app.connect('builder-inited', build_moduledocs)
