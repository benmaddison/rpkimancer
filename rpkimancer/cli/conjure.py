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

import argparse
import importlib.metadata
import ipaddress
import logging
import os
import typing

from . import Args, BaseCommand, Return
from .helpers import ip_resource, roa_network

if typing.TYPE_CHECKING:
    from ..cert import CertificateAuthority

log = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = os.path.join(os.curdir, "target", "demo")
PUB_SUB_DIR = "repo"
TAL_SUB_DIR = "tals"

DEFAULT_TA_AS_RESOURCES = [(0, 4294967295)]
DEFAULT_TA_IP_RESOURCES = [ipaddress.ip_network("0.0.0.0/0"),
                           ipaddress.ip_network("::0/0")]

DEFAULT_CA_AS_RESOURCES = [65000]
DEFAULT_CA_IP_RESOURCES = [ipaddress.ip_network("10.0.0.0/8"),
                           (ipaddress.ip_address("192.168.0.0"),
                            ipaddress.ip_address("192.168.2.255")),
                           ipaddress.ip_network("2001:db8::/32")]

DEFAULT_GBR_FULLNAME = "Jane Doe"
DEFAULT_GBR_ORG = "Example Org"
DEFAULT_GBR_EMAIL = "jane@example.net"

META_PATH = "<path>"
META_AS = "<asn>"
META_IP_PREFIX = "<prefix>/<length>"
META_IP_PREFIX_MAXLEN = f"{META_IP_PREFIX}[-maxlen]"
META_IP_RANGE = "<addr-lower>-<addr-upper>"
META_IP = f"{META_IP_PREFIX}|{META_IP_RANGE}"
META_NAME = "<name>"
META_ADDR = "<addr>"


class Conjure(BaseCommand):
    """Conjure a fully populated RPKI repository from thin air."""

    subcommand = "conjure"

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        """Initialise subcommand."""
        super().__init__(*args, **kwargs)
        log.info("trying to load plugins")
        self._plugins = list()
        entry_point_name = "rpkimancer.cli.conjure"
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
                                 metavar=META_PATH,
                                 help="Directory to write generated artifacts to "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--ta-as-resources",
                                 nargs="+", type=int,
                                 default=DEFAULT_TA_AS_RESOURCES,
                                 metavar=META_AS,
                                 help="ASN(s) to include in TA certificate "
                                      "(default: %(default)s)")
        self.parser.add_argument("--ta-ip-resources",
                                 nargs="+", type=ip_resource,
                                 default=DEFAULT_TA_IP_RESOURCES,
                                 metavar=META_IP,
                                 help="IP addresses to include in TA certificate "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--ca-as-resources",
                                 nargs="+", type=int,
                                 default=DEFAULT_CA_AS_RESOURCES,
                                 metavar=META_AS,
                                 help="ASN(s) to include in suboridinate CA certificate "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--ca-ip-resources",
                                 nargs="+", type=ip_resource,
                                 default=DEFAULT_CA_IP_RESOURCES,
                                 metavar=META_IP,
                                 help="IP addresses to include in suboridinate CA certificate "  # noqa: E501
                                      "(default: %(default)s)")
        self.parser.add_argument("--roa-asid",
                                 type=int,
                                 default=DEFAULT_CA_AS_RESOURCES[0],
                                 metavar=META_AS,
                                 help="ASN to include in ROA asID "
                                      "(default: %(default)s)")
        self.parser.add_argument("--roa-networks",
                                 nargs="+", type=roa_network,
                                 default=[(net, None)
                                          for net in DEFAULT_CA_IP_RESOURCES
                                          if isinstance(net, (ipaddress.IPv4Network,  # noqa: E501
                                                              ipaddress.IPv6Network))],  # noqa: E501
                                 metavar=META_IP_PREFIX_MAXLEN,
                                 help="IP prefixes to include in ROA "
                                      "(default: %(default)s)")
        self.parser.add_argument("--gbr-full-name",
                                 default=DEFAULT_GBR_FULLNAME,
                                 metavar=META_NAME,
                                 help="Full name to include in GBR "
                                      "(default: %(default)s)")
        self.parser.add_argument("--gbr-org",
                                 default=DEFAULT_GBR_ORG,
                                 metavar=META_NAME,
                                 help="Organisation name to include in GBR "
                                      "(default: %(default)s)")
        self.parser.add_argument("--gbr-email",
                                 default=DEFAULT_GBR_EMAIL,
                                 metavar=META_ADDR,
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
        plugin_publish_kwargs = dict()
        for plugin in self._plugins:
            log.info(f"running plugin {plugin}")
            if (kwargs := plugin(parsed_args, ca)) is not None:
                log.debug(f"{plugin} returned kwargs for publish: {kwargs}")
                plugin_publish_kwargs.update(kwargs)
        # publish objects
        log.info(f"publishing in-memory objects to {parsed_args.output_dir}")
        ta.publish(pub_path=os.path.join(parsed_args.output_dir, PUB_SUB_DIR),
                   tal_path=os.path.join(parsed_args.output_dir, TAL_SUB_DIR),
                   **plugin_publish_kwargs)
        return None


PluginReturn = typing.Optional[typing.Mapping[str, str]]


class ConjurePlugin:
    """Base class for conjure subcommand plugins."""

    def __init__(self, parent: argparse.ArgumentParser) -> None:
        """Initialise the plugin."""
        self.parser = parent
        self.init_parser()

    def __call__(self,
                 parsed_args: argparse.Namespace,
                 ca: CertificateAuthority,
                 *args: typing.Any,
                 **kwargs: typing.Any) -> PluginReturn:
        """Run the plugin."""
        return self.run(parsed_args, ca, *args, **kwargs)

    def init_parser(self) -> None:
        """Set up command line argument parser."""
        raise NotImplementedError

    def run(self,
            parsed_args: Args,
            ca: CertificateAuthority,
            *args: typing.Any,
            **kwargs: typing.Any) -> PluginReturn:
        """Run with the given arguments, returning extra publish kwargs."""
        raise NotImplementedError
