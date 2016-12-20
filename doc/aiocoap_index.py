import functools
import re

from docutils.parsers.rst.directives.misc import Include

rtd_re = re.compile("^\\.\\. _([^:]+): http://aiocoap.readthedocs.io/en/latest/(.*)\\.html$")
filelink_re = re.compile("^\\.\\. _([^:]+): ([^:]+)$")

def modified_insert_input(include_lines, path, original=None):
    new_lines = []
    replacements = {}
    for line in include_lines:
        rtd_match = rtd_re.match(line)
        filelink_match = filelink_re.match(line)
        if rtd_match:
            pattern, linkbody = rtd_match.groups()
            if 'module' in pattern: # dirty hint
                sphinxlink = ':mod:`%s`'%linkbody
            else:
                sphinxlink = ':doc:`%s`'%linkbody
            replacements[pattern + '_'] = sphinxlink
            # and drop the line
        elif filelink_match:
            # for things like LICENSE
            pattern, linkbody = filelink_match.groups()
            replacements[pattern + '_'] = ':doc:`%s`'%linkbody
        else:
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


def setup(app):
    """Sphinx extension that builds the aiocoap index page from a non-sphinx
    and thus github-suitable ReST file, and also creates sphinx-apidoc style
    per-module pages customized to what I'd like to see there"""

    app.add_directive('include_preprocessed', IncludePreprocessed)
