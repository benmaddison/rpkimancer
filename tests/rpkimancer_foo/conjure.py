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
"""rpkincant conjure plugins for RPKI Foo Objects."""

from __future__ import annotations

import logging
import typing

from rpkimancer.cli import Args
from rpkimancer.cli.conjure import ConjurePlugin, PluginReturn

if typing.TYPE_CHECKING:
    from rpkimancer.cert import CertificateAuthority

log = logging.getLogger(__name__)


class ConjureFoo(ConjurePlugin):
    """rpkincant conjure plugin for RPKI Foo Objects."""

    def init_parser(self) -> None:
        """Set up command line argument parser."""
        self.parser.add_argument("--foo-content",
                                 default="Hello World!",
                                 metavar="<text>",
                                 help="Text string to encode into foo object "
                                      "(default: %(default)s)")

    def run(self,
            parsed_args: Args,
            ca: CertificateAuthority,
            *args: typing.Any,
            **kwargs: typing.Any) -> PluginReturn:
        """Run with the given arguments."""
        # create RSC object
        from .sigobj import FooObject
        log.info("creating foo object")
        FooObject(issuer=ca, content=parsed_args.foo_content)
        return
