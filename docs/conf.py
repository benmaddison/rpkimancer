# Copyright (c) 2021 Ben Maddison. All rights reserved.
#
# The contents of this file are licensed under the MIT License
# (the "License"); you may not use this file except in compliance with the
# License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""rpkimancer documentation config."""

from __future__ import annotations

import datetime
import importlib.metadata
import pathlib

import docutils

import rpkimancer

import sphinx_readable_theme

import yaml

_dist = importlib.metadata.distribution(rpkimancer.__name__)
_buildtime = datetime.datetime.utcnow()

# -- Project Information

project = _dist.metadata["name"]
author = _dist.metadata["author"]

_from_year = 2021
_to_year = _buildtime.year
if _from_year < _to_year:
    _year_range = f"{_from_year}-{_to_year}"
else:
    _year_range = f"{_from_year}"
copyright = f"{_year_range}, {author}"

release = _dist.version
version = ".".join(release.split(".")[:2])


# -- General configuration

extensions = [
    "sphinx.ext.autodoc",
    "myst_parser",
    "sphinx_multiversion",
]
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
exclude_patterns = []
templates_path = ['_templates']

# -- HTML output

html_theme = 'readable'
html_theme_path = [sphinx_readable_theme.get_html_theme_path()]
html_static_path = ['_static']
html_sidebars = {
    "**": [
        "localtoc.html",
        "relations.html",
        "versions.html",
        "searchbox.html",
    ],
}

# -- Autodoc configuration

autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_typehints_description_target = "all"

# -- Markdown processing

myst_enable_extensions = [
    "colon_fence",
]

# -- Multiversion processing

smv_branch_whitelist = r"^(?!pyup-|gh-pages).*$"
smv_remote_whitelist = r"^origin$"
smv_prebuild_command = "sphinx-apidoc --separate " \
                                     "--force " \
                                     "--output-dir docs/generated/ " \
                                     "rpkimancer/"

# -- OID registry construction

class OidRegistry(docutils.parsers.rst.Directive):

    has_content = False
    required_arguments = 0
    option_spec = {
        "path": docutils.parsers.rst.directives.unchanged_required,
    }

    def run(self):
        registry_path = pathlib.Path(__file__).parent / self.options["path"]
        with open(registry_path) as f:
            data = yaml.safe_load(f)
        root = data["root"]
        arc = data["arc"]

        table = docutils.nodes.table()
        tgroup = docutils.nodes.tgroup(cols=2)
        for w in range(2):
            colspec = docutils.nodes.colspec(colwidth=w + 1)
            tgroup.append(colspec)
        table += tgroup

        thead = docutils.nodes.thead()
        tgroup += thead
        row = docutils.nodes.row()
        for col in ("OID", "Details"):
            entry = docutils.nodes.entry()
            entry += docutils.nodes.paragraph(text=col)
            row += entry
        thead.append(row)

        body = self.render_arc(root, arc)
        tgroup += body

        return [table]

    def render_arc(self, root_oid, arc, body=None):
        if body is None:
            body = docutils.nodes.tbody()
        for roid, info in arc.items():
            oid = f"{root_oid}.{roid}"
            body.append(self.render_oid_row(oid, info))
            try:
                if (sub_arc := info.get("arc")) is not None:
                    self.render_arc(oid, sub_arc, body=body)
            except AttributeError:
                continue
        return body

    def render_oid_row(self, oid, info):
        row = docutils.nodes.row()

        oid_cell = docutils.nodes.entry()
        oid_para = docutils.nodes.paragraph()
        oid_para += docutils.nodes.literal(text=oid)
        oid_cell += oid_para
        row += oid_cell

        details_cell = docutils.nodes.entry()
        if isinstance(info, str):
            details = [docutils.nodes.paragraph(text=f"{info}")]
        else:
            name = docutils.nodes.paragraph()
            name += docutils.nodes.literal(text=info["name"])
            description = docutils.nodes.paragraph(text=info["description"])
            details = [name, description]
            try:
                for uri in info["refs"]:
                    ref_para = docutils.nodes.paragraph()
                    ref = docutils.nodes.reference(internal=False, refuri=uri, text=uri)
                    ref_para += ref
                    details.append(ref_para)
            except KeyError:
                pass
        details_cell.extend(details)
        row += details_cell

        return row


def setup(app):
    app.add_directive("oid-registry", OidRegistry)
    return {"version": "0.1",
            "parallel_read_safe": True,
            "parallel_write_safe": True}
