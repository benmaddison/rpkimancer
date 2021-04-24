# PYTHON_ARGCOMPLETE_OK
#
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
"""rpkincant CLI tool entrypoint."""

from __future__ import annotations

import importlib.metadata
import logging
import typing

from . import Args, BaseCommand, OptionalArgv, Return

log = logging.getLogger(__name__)


class Cli(BaseCommand):
    """Command-line tools based on the rpkimancer library."""

    from .perceive import Perceive
    from .conjure import Conjure

    default_subcommands = [Conjure, Perceive]

    def init_parser(self) -> None:
        """Set up command line argument parser."""
        subcommands = self.default_subcommands
        log.info("trying to load plugins")
        entry_point_name = "rpkimancer.cli-plugin"
        entry_points = importlib.metadata.entry_points()
        for entry_point in entry_points.get(entry_point_name, []):
            cls = entry_point.load()
            if issubclass(cls, BaseCommand):
                subcommands.append(cls)
        subparsers = self.parser.add_subparsers(title="sub-commands",
                                                metavar="<command>",
                                                dest="cmd", required=True)
        for cls in subcommands:
            cls(parent=subparsers)

    def run(self,
            parsed_args: Args,
            *args: typing.Any,
            **kwargs: typing.Any) -> Return:
        """Run with the given arguments."""
        log.info("running sub-command {parsed_args.cmd}")
        rc = parsed_args.run(parsed_args)
        return typing.cast(Return, rc)


def main(argv: OptionalArgv = None) -> Return:
    """Read RPKI artifacts."""
    cli = Cli()
    return cli(argv)
