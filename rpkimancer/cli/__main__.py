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
"""Main CLI tool entrypoint."""

from __future__ import annotations

import logging
import typing

from . import Args, BaseCommand, OptionalArgv, Return

log = logging.getLogger(__name__)


class Cli(BaseCommand):
    """Command-line tools based on the rpkimancer library."""

    from .augur import Augur
    from .conjure import Conjure

    default_subcommands = (Augur, Conjure)

    def init_parser(self) -> None:
        """Set up command line argument parser."""
        subcommands = self.default_subcommands
        subparsers = self.parser.add_subparsers(title="sub-commands",
                                                metavar="<command>",
                                                dest="cmd", required=True)
        for cls in subcommands:
            cls(parent=subparsers)

    def run(self, args: Args) -> Return:
        """Run with the given arguments."""
        log.info("running sub-command {args.cmd}")
        rc = args.run(args)
        return typing.cast(Return, rc)


def main(argv: OptionalArgv = None) -> Return:
    """Read RPKI artifacts."""
    cli = Cli()
    return cli(argv)
