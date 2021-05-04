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

import sphinx_readable_theme

import rpkimancer

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
    "sphinx_autodoc_typehints",
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

# -- Markdown processing

myst_enable_extensions = [
    "colon_fence",
]

# -- Typehint processing

always_document_param_types = True

# -- Multiversion processing

smv_prebuild_command = "sphinx-apidoc --separate " \
                                     "--force " \
                                     "--output-dir docs/generated/ " \
                                     "rpkimancer/"
