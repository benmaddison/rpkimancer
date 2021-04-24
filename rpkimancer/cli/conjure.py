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
"""rpki-conjure command implementation."""

from __future__ import annotations

import importlib.metadata
import ipaddress
import logging
import os
import typing

from . import Args, BaseCommand, Return

if typing.TYPE_CHECKING:
    from ..cert import CertificateAuthority
    from ..sigobj.roa import RoaNetworkInfo

log = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = os.path.join(os.curdir, "target", "demo")
PUB_SUB_DIR = "repo"
TAL_SUB_DIR = "tals"

DEFAULT_TA_AS_RESOURCES = [(0, 4294967295)]
DEFAULT_TA_IP_RESOURCES = [ipaddress.ip_network("0.0.0.0/0"),
                           ipaddress.ip_network("::0/0")]

DEFAULT_CA_AS_RESOURCES = [65000]
DEFAULT_CA_IP_RESOURCES = [ipaddress.ip_network("10.0.0.0/8"),
                           ipaddress.ip_network("2001:db8::/32")]

DEFAULT_GBR_FULLNAME = "Jane Doe"
DEFAULT_GBR_ORG = "Example Org"
DEFAULT_GBR_EMAIL = "jane@example.net"

PATH_META = "<path>"
AS_META = "<asn>"
IP_META = "<prefix>/<length>"
ROA_IP_META = f"{IP_META}[-maxlen]"
NAME_META = "<name>"
ADDR_META = "<addr>"


class Conjure(BaseCommand):
    """Conjure a fully populated RPKI repository from thin air."""

    subcommand = "conjure"

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        """Initialise subcommand."""
        super().__init__(*args, **kwargs)
        log.info("trying to load plugins")
        self._plugins = list()
        entry_point_name = "rpkimancer.cli.conjure-plugin"
        entry_points = importlib.metadata.entry_points()
        for entry_point in entry_points.get(entry_point_name, []):
            cls = entry_point.load()
            if issubclass(cls, ConjurePlugin):
                plugin = cls(self.parser)
                self._plugins.append(plugin)

    def init_parser(self) -> None:
        """Set up command line argument parser."""
        self.parser.add_argument("--output-dir", "-o",
                                 default=DEFAULT_OUTPUT_DIR,
                                 metavar=PATH_META,
                                 help="Directory to write generated artifacts to "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--ta-as-resources",
                                 nargs="+", type=int,
                                 default=DEFAULT_TA_AS_RESOURCES,
                                 metavar=AS_META,
                                 help="ASN(s) to include in TA certificate "
                                      "(default: %(default)s)")
        self.parser.add_argument("--ta-ip-resources",
                                 nargs="+", type=ipaddress.ip_network,
                                 default=DEFAULT_TA_IP_RESOURCES,
                                 metavar=IP_META,
                                 help="IP addresses to include in TA certificate "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--ca-as-resources",
                                 nargs="+", type=int,
                                 default=DEFAULT_CA_AS_RESOURCES,
                                 metavar=AS_META,
                                 help="ASN(s) to include in suboridinate CA certificate "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--ca-ip-resources",
                                 nargs="+", type=ipaddress.ip_network,
                                 default=DEFAULT_CA_IP_RESOURCES,
                                 metavar=IP_META,
                                 help="IP addresses to include in suboridinate CA certificate "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--roa-asid",
                                 type=int,
                                 default=DEFAULT_CA_AS_RESOURCES[0],
                                 metavar=AS_META,
                                 help="ASN to include in ROA asID "
                                      "(default: %(default)s)")
        self.parser.add_argument("--roa-networks",
                                 nargs="+", type=self._roa_network,
                                 default=[(ipaddress.ip_network(net), None)
                                          for net in DEFAULT_CA_IP_RESOURCES],
                                 metavar=ROA_IP_META,
                                 help="IP prefixes to include in ROA "
                                      "(default: %(default)s)")
        self.parser.add_argument("--gbr-full-name",
                                 default=DEFAULT_GBR_FULLNAME,
                                 metavar=NAME_META,
                                 help="Full name to include in GBR "
                                      "(default: %(default)s)")
        self.parser.add_argument("--gbr-org",
                                 default=DEFAULT_GBR_ORG,
                                 metavar=NAME_META,
                                 help="Organisation name to include in GBR "
                                      "(default: %(default)s)")
        self.parser.add_argument("--gbr-email",
                                 default=DEFAULT_GBR_EMAIL,
                                 metavar=ADDR_META,
                                 help="Email address to include in GBR "
                                      "(default: %(default)s)")

    def run(self,
            parsed_args: Args,
            *args: typing.Any,
            **kwargs: typing.Any) -> Return:
        """Run with the given arguments."""
        log.info("setting up rpkimancer library objects")
        from ..cert import CertificateAuthority, TACertificateAuthority
        from ..sigobj import RouteOriginAttestation, RpkiGhostbusters
        # create CAs
        log.info("creating TA certificate authority")
        ta = TACertificateAuthority(as_resources=parsed_args.ta_as_resources,
                                    ip_resources=parsed_args.ta_ip_resources)
        log.info("creating suboridinate certificate authority")
        ca = CertificateAuthority(issuer=ta,
                                  as_resources=parsed_args.ca_as_resources,
                                  ip_resources=parsed_args.ca_ip_resources)
        # create ROA
        log.info("creating ROA object")
        RouteOriginAttestation(issuer=ca,
                               as_id=parsed_args.roa_asid,
                               ip_address_blocks=parsed_args.roa_networks)
        # create GBR
        log.info("creating ghostbusters record object")
        RpkiGhostbusters(issuer=ca,
                         full_name=parsed_args.gbr_full_name,
                         org=parsed_args.gbr_org,
                         email=parsed_args.gbr_email)
        # run plugins
        log.info("running plugins")
        for plugin in self._plugins:
            log.info("running plugin {plugin}")
            plugin(parsed_args, ca)
        # publish objects
        log.info(f"publishing in-memory objects to {parsed_args.output_dir}")
        ta.publish(pub_path=os.path.join(parsed_args.output_dir, PUB_SUB_DIR),
                   tal_path=os.path.join(parsed_args.output_dir, TAL_SUB_DIR))
        return None

    @staticmethod
    def _roa_network(input_str: str) -> RoaNetworkInfo:
        """Convert input string to RoaNetworkInfo tuple."""
        try:
            network, maxlen = input_str.split("-", 1)
            return (ipaddress.ip_network(network), int(maxlen))
        except ValueError:
            return (ipaddress.ip_network(input_str), None)


class ConjurePlugin(BaseCommand):
    """Base class for conjure subcommand plugins."""

    def run(self,
            parsed_args: Args,
            ca: typing.Optional[CertificateAuthority] = None,
            *args: typing.Any,
            **kwargs: typing.Any) -> Return:
        """Run with the given arguments."""
        raise NotImplementedError
