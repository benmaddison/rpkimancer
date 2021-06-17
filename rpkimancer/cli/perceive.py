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
"""rpkincant perceive command implementation."""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import sys
import typing

from . import Args, BaseCommand, Return

if typing.TYPE_CHECKING:
    from rpkimancer.asn1 import Interface

log = logging.getLogger(__name__)

WriteGenerator = typing.Generator[typing.Callable[["Interface", str], None],
                                  None,
                                  None]


class Perceive(BaseCommand):
    """Learn of the secrets carried within an RPKI signed object."""

    subcommand = "perceive"
    usage = None

    def init_parser(self) -> None:
        """Set up command line argument parser."""
        self.parser.add_argument("paths", nargs="+",
                                 metavar="<file-path>",
                                 help="Path to the signed object")
        self.parser.add_argument("--output", "-o",
                                 metavar="<output-path>",
                                 type=self._output, default=self._output(),
                                 help="Path to output file "
                                      "(default: STDOUT)")
        info_group = self.parser.add_argument_group("output options")
        info = info_group.add_mutually_exclusive_group()
        self.parser.set_defaults(info_property="econtent")
        info.add_argument("--signed-data", "-S", dest="info_property",
                          action="store_const", const=None,
                          help="Print decoded SignedData")
        info.add_argument("--econtent-info", "-I", dest="info_property",
                          action="store_const", const="econtent_info",
                          help="Print decoded EncapsulatedContentInfo")
        info.add_argument("--econtent", "-E", dest="info_property",
                          action="store_const", const="econtent",
                          help="Print decoded eContent (default)")
        fmt_group = self.parser.add_argument_group("format options")
        fmt = fmt_group.add_mutually_exclusive_group()
        self.parser.set_defaults(fmt_method="to_txt")
        fmt.add_argument("--asn1", "-A", dest="fmt_method",
                         action="store_const", const="to_asn1",
                         help="Output ASN.1 data syntax")
        fmt.add_argument("--json", "-j", dest="fmt_method",
                         action="store_const", const="to_json",
                         help="Output JSON encoded data")
        fmt.add_argument("--jer", "-J", dest="fmt_method",
                         action="store_const", const="to_jer",
                         help="Output JER encoded data")
        fmt.add_argument("--raw", "-R", dest="fmt_method",
                         action="store_const", const="to_internal",
                         help="Output internal python data representation")

    def run(self,
            parsed_args: Args,
            *args: typing.Any,
            **kwargs: typing.Any) -> Return:
        """Run with the given arguments."""
        log.info("setting up rpkimancer library objects")
        from ..sigobj import from_ext
        objects = list()
        for path in parsed_args.paths:
            log.info(f"deciphering {path}")
            _, ext = os.path.splitext(path)
            if not ext:
                continue
            log.info(f"trying to get object type for file extension {ext}")
            try:
                object_cls = from_ext(ext)
            except KeyError:
                log.warning(f"no signed object type with file extension {ext}")
                continue
            log.info(f"trying to read signed object from {path}")
            with open(path, "rb") as f:
                data = f.read()
            log.info(f"trying to deserialise to {object_cls}")
            obj = object_cls.from_der(data)
            objects.append(obj)
        with parsed_args.output as write:
            for obj in objects:
                write(obj, parsed_args.info_property, parsed_args.fmt_method)
        return None

    @staticmethod
    @contextlib.contextmanager
    def _output(path: typing.Optional[str] = None) -> WriteGenerator:

        def _write(obj: Interface,
                   info_property: typing.Optional[str],
                   fmt_method: str,
                   f: typing.TextIO) -> None:
            if info_property is not None:
                obj = getattr(obj, info_property)
            func = getattr(obj, fmt_method)
            f.write(f"{func()}\n")

        if path is None:
            yield functools.partial(_write, f=sys.stdout)
        else:
            with open(path, "w") as f:
                yield functools.partial(_write, f=f)
