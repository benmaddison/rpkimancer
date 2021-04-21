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
"""Learn of the secrets carried within an RPKI signed object."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import typing

import argcomplete

if typing.TYPE_CHECKING:
    from rpkimancer.asn1 import Content
    from rpkimancer.sigobj import SignedObject

log = logging.getLogger(__name__)

OBJ_META = "<file-path>"

ArgvType = typing.List[str]


def parse_args(argv: ArgvType) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     usage="%(prog)s [options]")
    parser.add_argument("path",
                        metavar=OBJ_META,
                        help="Path to the signed object")
    parser.add_argument("--signed-data", "-S",
                        action="store_true", default=False,
                        help="Print decoded SignedData structure")
    parser.add_argument("--econtent", "-E",
                        action="store_false", default=True,
                        help="Don't print decoded eContent")
    fmt = parser.add_mutually_exclusive_group()
    parser.set_defaults(fmt_method="to_asn1")
    fmt.add_argument("--asn1", "-A",
                     action="store_const", const="to_asn1", dest="fmt_method",
                     help="Output ASN.1 data syntax")
    fmt.add_argument("--json", "-J",
                     action="store_const", const="to_json", dest="fmt_method",
                     help="Output JSON-encoded data")
    parser.add_argument("-v", action="count", default=0, dest="verbosity",
                        help="Increase logging verbosity")
    argcomplete.autocomplete(parser, always_complete_options="long")
    return parser.parse_args(argv)


def set_log_level(verbosity: int) -> None:
    """Set logging verbosity."""
    level = logging.WARNING - (10 * verbosity)
    logging.basicConfig(level=level)


def print_object(obj: SignedObject,
                 signed_data: bool,
                 econtent: bool,
                 fmt_method: str) -> None:
    """Print the object in the requested serialization format."""

    def _output(obj: Content) -> str:
        func = getattr(obj, fmt_method)
        return typing.cast(str, func())

    if signed_data:
        print(_output(obj))
    if econtent:
        print(_output(obj.econtent))


def main(argv: typing.Optional[ArgvType] = None) -> typing.Optional[int]:
    """Read RPKI artifacts."""
    try:
        # get command line args
        if argv is None:
            argv = sys.argv[1:]
        args = parse_args(argv)
        set_log_level(args.verbosity)
        # import rpkimancer types
        log.info("setting up rpkimancer library objects")
        from ..sigobj import from_ext
        # read DER encoded object from file
        log.info(f"trying to read signed object from {args.path}")
        with open(args.path, "rb") as f:
            data = f.read()
        # determine the type to deserialise into
        _, ext = os.path.splitext(args.path)
        log.info(f"trying to determine object type from file extension {ext}")
        object_cls = from_ext(ext)
        # deserialise DER encoded data
        log.info(f"trying to deserialise to {object_cls}")
        obj = object_cls.from_der(data)
        # output decoded structure
        print_object(obj, args.signed_data, args.econtent, args.fmt_method)
    except KeyboardInterrupt:
        log.error("Interrupted by Ctrl+C")
        return 2
    except Exception as e:
        log.error(f"{e!r}", exc_info=(args.verbosity >= 3))
        return 1
    return None
