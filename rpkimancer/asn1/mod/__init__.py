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
"""Compile and re-export the provided ASN.1 modules."""
from __future__ import annotations

import glob
import logging
import os

import pycrate_asn1c.asnproc as _asn1_compile
import pycrate_asn1c.generator as _asn1_generate

from .. import log_level_parser
from ...utils import LogWriter

log = logging.getLogger(__name__)
log_writer = LogWriter(log, level_cb=log_level_parser)


def _compile_modules() -> None:
    log.info("Trying to compile ASN.1 modules sources")
    pkg_dir = os.path.dirname(__file__)
    mods_dir = os.path.join(pkg_dir, "modules")
    output_path = os.path.join(pkg_dir, "_mod.py")
    mods = list()
    for path in glob.glob(os.path.join(mods_dir, "**", "*.asn")):
        log.debug(f"Reading {path}")
        with open(path) as f:
            mods.append(f.read())
    with log_writer.redirect_stdout():
        _asn1_compile.compile_text(mods)
        _asn1_generate.PycrateGenerator(dest=output_path)
    log.info("Compilation done")


_compile_modules()
from ._mod import *  # noqa
