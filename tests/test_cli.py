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
"""rpkimancer CLI tests package."""

from __future__ import annotations

import copy
import importlib.abc
import importlib.metadata
import logging
import os
import subprocess
import sys

import pytest

log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def target_directory(tmp_path_factory):
    """Set up a tmp directory for writing artifacts."""
    return tmp_path_factory.mktemp("target")


@pytest.fixture(scope="session")
def patch_meta_path():
    """Inject a dummy plugin distribution into 'meta_path'."""

    class DummyDistribution(importlib.metadata.Distribution):
        def read_text(self, filename):
            if filename == "PKG-INFO":
                text = ["Metadata-Version: 2.1",
                        "Name: rpkimancer-foo",
                        "Version: 0.0.1"]
            elif filename == "entry_points.txt":
                text = ["[rpkimancer.asn1.modules]",
                        "RpkiFoo = rpkimancer_foo.asn1",
                        "[rpkimancer.cli.conjure]",
                        "ConjureFoo = rpkimancer_foo.conjure:ConjureFoo",
                        "[rpkimancer.sigobj]",
                        "FooObject = rpkimancer_foo.sigobj:FooObject"]
            else:
                text = None
            return "\n".join(text)

        def locate_file(self, path):
            raise NotImplementedError

    dummy_finder_ctx = importlib.metadata.DistributionFinder.Context()

    class DummyMetaPathFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path, target=None):
            return None

        def find_distributions(self, context=dummy_finder_ctx):
            yield DummyDistribution()

    try:
        old_meta_path = copy.copy(sys.meta_path)
        sys.meta_path.append(DummyMetaPathFinder)
        yield
    finally:
        sys.meta_path = old_meta_path


@pytest.mark.usefixtures("patch_meta_path")
class TestCli:
    """Test cases for rpkimancer CLI tools."""

    def test_conjure(self, target_directory):
        """Test the conjure subcommand."""
        from rpkimancer.cli.__main__ import main
        argv = ["conjure", "--output-dir", f"{target_directory}"]
        retval = main(argv)
        assert retval is None

    @pytest.mark.parametrize("out", (None, "-E", "-I", "-S"))
    @pytest.mark.parametrize("fmt", (None, "-A", "-j", "-J", "-R"))
    @pytest.mark.parametrize("ext", ("gbr", "mft", "roa"))
    def test_perceive(self, target_directory, ext, fmt, out):
        """Test the perceive subcommand."""
        from rpkimancer.cli.__main__ import main
        repo_path = target_directory / "repo"
        paths = repo_path.rglob(f"*.{ext}")
        argv = ["perceive",
                "--output", os.devnull]
        if fmt is not None:
            argv.append(fmt)
        if out is not None:
            argv.append(out)
        argv.extend(str(p) for p in paths)
        retval = main(argv)
        assert retval is None

    @pytest.mark.rpki_client
    @pytest.mark.parametrize("iteration", range(10))
    def test_rpki_validate(self, tmp_path_factory, iteration):
        """Test rpki-client can validate the generated artifacts."""
        target_directory = tmp_path_factory.mktemp("target")
        from rpkimancer.cli.__main__ import main
        argv = ["conjure", "--output-dir", f"{target_directory}"]
        retval = main(argv)
        assert retval is None
        cmd = ["rpki-client", "-jnvv"]
        repo_path = target_directory / "repo"
        cmd.extend(("-d", str(repo_path)))
        tal_paths = (target_directory / "tals").glob("*.tal")
        for tal_path in tal_paths:
            cmd.extend(("-t", str(tal_path)))
        output_path = target_directory / "output"
        output_path.mkdir(exist_ok=True)
        cmd.append(str(output_path))
        proc = subprocess.run(cmd,
                              text=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        output = proc.stdout
        valid = True
        for line in output.rstrip().splitlines():
            if "signature failure" in line:
                level = logging.ERROR
                valid = False
            else:
                level = logging.INFO
            log.log(level, line.strip())
        assert proc.returncode == 0
        assert valid
