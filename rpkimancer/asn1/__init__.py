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
import glob
import importlib.resources
import os

import pycrate_asn1c.asnproc as _asn1_compile
import pycrate_asn1c.generator as _asn1_generate


def _compile_modules():
    pkg_dir = os.path.dirname(__file__)
    mods_dir = os.path.join(pkg_dir, "modules")
    mods = list()
    for path in glob.glob(os.path.join(mods_dir, "**", "*.asn")):
        with open(path) as f:
            mods.append(f.read())
    _asn1_compile.compile_text(mods)
    output_path = os.path.join(pkg_dir, "_asn1.py")
    _asn1_generate.PycrateGenerator(dest=output_path)


_compile_modules()
from ._asn1 import *  # noqa
