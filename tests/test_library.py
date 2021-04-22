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
"""rpkimancer package tests."""

from __future__ import annotations

import pytest

import rpkimancer


@pytest.fixture(scope="session")
def target_directory(tmpdir_factory):
    """Set up a tmp directory for writing artifacts."""
    return tmpdir_factory.mktemp("target")


class TestLibrary:
    """Test cases for the rpkimancer library."""

    def test_dummy(self):
        """Dummy test."""
        assert rpkimancer


class TestCli:
    """Test cases for rpkimancer CLI tools."""

    def test_conjure(self, target_directory):
        """Test the rpki-conjure CLI tool."""
        from rpkimancer.cli.__main__ import main
        argv = ["conjure", "--output-dir", f"{target_directory}"]
        retval = main(argv)
        assert retval is None

    def test_augur(self, target_directory):
        """Test the rpki-augur CLI tool."""
        from rpkimancer.cli.__main__ import main
        path = target_directory.join("repo", "rpki.example.net",
                                     "rpki", "TA", "manifest.mft")
        argv = ["augur", str(path)]
        retval = main(argv)
        assert retval is None