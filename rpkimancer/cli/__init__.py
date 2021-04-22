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
"""Modules implementing CLI tools using rpkimancer."""

from __future__ import annotations

import argparse
import logging
import sys
import typing

import argcomplete

log = logging.getLogger(__name__)

OptionalSubParser = typing.Optional[argparse._SubParsersAction]
Args = argparse.Namespace
OptionalArgv = typing.Optional[typing.List[str]]
OptionalArgs = typing.Union[Args, OptionalArgv]
Return = typing.Optional[int]


def set_log_level(verbosity: int) -> None:
    """Set logging verbosity."""
    level = logging.WARNING - (10 * verbosity)
    logging.basicConfig(level=level)


class BaseCommand:
    """Base class for command-line utilities."""

    subcommand: str
    usage: typing.Optional[str] = "%(prog)s [options]"

    def __init__(self, parent: OptionalSubParser = None) -> None:
        """Initialise the command."""
        description = self.__doc__
        if parent is None:
            parser = argparse.ArgumentParser(description=description,
                                             usage=self.usage)
            parser.add_argument("-v", dest="verbosity",
                                action="count", default=0,
                                help="Increase logging verbosity")
        else:
            parser = parent.add_parser(self.subcommand,
                                       description=description,
                                       help=description)
            parser.set_defaults(run=self)
        self.parser = parser
        self.init_parser()

    def __call__(self, args_or_argv: OptionalArgs = None) -> Return:
        """Run the command."""
        if isinstance(args_or_argv, Args):
            args = args_or_argv
        else:
            argcomplete.autocomplete(self.parser,
                                     always_complete_options="long")
            if args_or_argv is None:  # pragma: no cover
                argv = sys.argv[1:]
            else:
                argv = args_or_argv
            args = self.parser.parse_args(argv)
            set_log_level(args.verbosity)
        try:
            return self.run(args)
        except KeyboardInterrupt:  # pragma: no cover
            log.error("Interrupted by Ctrl+C")
            return 2
        except Exception as e:  # pragma: no cover
            log.error(f"{e!r}", exc_info=(args.verbosity >= 3))
            return 1

    def init_parser(self) -> None:
        """Set up command line argument parser."""
        raise NotImplementedError

    def run(self, args: Args) -> Return:
        """Run with the given arguments."""
        raise NotImplementedError
