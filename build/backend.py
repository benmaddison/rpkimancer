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
"""In-tree build backend for rpkimancer package."""

import glob
import subprocess
import os

import setuptools.build_meta as s


prepare_metadata_for_build_wheel = s.prepare_metadata_for_build_wheel
get_requires_for_build_wheel = s.get_requires_for_build_wheel
get_requires_for_build_sdist = s.get_requires_for_build_sdist


def _generate_asn1_module():
    base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)))
    asn1_modules_pattern = os.path.join(base_dir, "modules", "**", "*.asn")
    asn1_modules = glob.glob(asn1_modules_pattern, recursive=True)
    output_module = os.path.join(base_dir, "rpkimancer", "asn1")
    compile_cmd = ["pycrate_asn1compile.py",
                   "-o", output_module,
                   "-i"]
    compile_cmd.extend(asn1_modules)
    subprocess.run(compile_cmd, check=True)


def build_sdist(*args, **kwargs):
    _generate_asn1_module()
    return s.build_sdist(*args, **kwargs)


def build_wheel(*args, **kwargs):
    _generate_asn1_module()
    return s.build_wheel(*args, **kwargs)
