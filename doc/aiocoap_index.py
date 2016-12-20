import functools
import re
import os
import tempfile
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
    pretty = pattern.strip('`')
    if pretty != linkbody:
        sphinxlink = ':%s:`%s <%s>`'%(prefix, pretty, linkbody)
    else:
        sphinxlink = ':%s:`%s`'%(prefix, linkbody)
    replacements[pattern + '_'] = sphinxlink

def modified_insert_input(include_lines, path, original=None):
    new_lines = []
    replacements = {}
    for line in include_lines:
        rtd_match = rtd_re.match(line)
        filelink_match = filelink_re.match(line)
        if rtd_match:
            pattern, linkbody = rtd_match.groups()
            if 'module' in pattern: # dirty hint
                prefix = 'mod'
            else:
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
    def run(self):
        self.state_machine.insert_input = functools.partial(modified_insert_input, original=self.state_machine.insert_input)
        try:
            result = super().run()
        finally:
            del self.state_machine.insert_input
        return result

def build_moduledocs(app):
    srcdir = app.builder.srcdir

    moddir = srcdir + '/module'
    os.makedirs(moddir, exist_ok=True)

    basedir = os.path.dirname(srcdir)
    docs = [x[len(basedir)+1:-3].replace('/', '.').replace('.__init__', '') for x in glob35(basedir + '/aiocoap/**/*.py', recursive=True)]

    for x in docs:
        text = textwrap.dedent("""\
            {x} module
            ========================================
            """).format(x=x)
        if x == 'aiocoap.numbers':
            text += textwrap.dedent("""
                .. automodule:: {x}
                .. toctree::
                    :glob:

                    aiocoap.numbers.*
                """).format(x=x)
        else:
            text += textwrap.dedent("""
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
