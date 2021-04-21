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
"""Conjure a fully populated RPKI repository from thin air."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
import typing

import argcomplete

if typing.TYPE_CHECKING:
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

ArgvType = typing.List[str]


def parse_args(argv: ArgvType) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     usage="%(prog)s [options]")
    parser.add_argument("--output-dir", "-o",
                        default=DEFAULT_OUTPUT_DIR,
                        metavar=PATH_META,
                        help="Directory to write generated artifacts to "
                             "(default: %(default)s)")
    parser.add_argument("--ta-as-resources",
                        nargs="+", type=int,
                        default=DEFAULT_TA_AS_RESOURCES,
                        metavar=AS_META,
                        help="ASN(s) to include in TA certificate "
                             "(default: %(default)s)")
    parser.add_argument("--ta-ip-resources",
                        nargs="+", type=ipaddress.ip_network,
                        default=DEFAULT_TA_IP_RESOURCES,
                        metavar=IP_META,
                        help="IP addresses to include in TA certificate "
                             "(default: %(default)s)")
    parser.add_argument("--ca-as-resources",
                        nargs="+", type=int,
                        default=DEFAULT_CA_AS_RESOURCES,
                        metavar=AS_META,
                        help="ASN(s) to include in suboridinate CA certificate "  # noqa: E501
                             "(default: %(default)s)")
    parser.add_argument("--ca-ip-resources",
                        nargs="+", type=ipaddress.ip_network,
                        default=DEFAULT_CA_IP_RESOURCES,
                        metavar=IP_META,
                        help="IP addresses to include in suboridinate CA certificate "  # noqa: E501
                             "(default: %(default)s)")
    parser.add_argument("--roa-asid",
                        type=int,
                        default=DEFAULT_CA_AS_RESOURCES[0],
                        metavar=AS_META,
                        help="ASN to include in ROA asID "
                             "(default: %(default)s)")
    parser.add_argument("--roa-networks",
                        nargs="+", type=roa_network,
                        default=[(ipaddress.ip_network(net), None)
                                 for net in DEFAULT_CA_IP_RESOURCES],
                        metavar=ROA_IP_META,
                        help="IP prefixes to include in ROA "
                             "(default: %(default)s)")
    parser.add_argument("--gbr-full-name",
                        default=DEFAULT_GBR_FULLNAME,
                        metavar=NAME_META,
                        help="Full name to include in GBR "
                             "(default: %(default)s)")
    parser.add_argument("--gbr-org",
                        default=DEFAULT_GBR_ORG,
                        metavar=NAME_META,
                        help="Organisation name to include in GBR "
                             "(default: %(default)s)")
    parser.add_argument("--gbr-email",
                        default=DEFAULT_GBR_EMAIL,
                        metavar=ADDR_META,
                        help="Email address to include in GBR "
                             "(default: %(default)s)")
    parser.add_argument("-v", action="count", default=0, dest="verbosity",
                        help="Increase logging verbosity")
    argcomplete.autocomplete(parser, always_complete_options="long")
    return parser.parse_args(argv)


def roa_network(input_str: str) -> RoaNetworkInfo:
    """Convert input string to RoaNetworkInfo tuple."""
    try:
        network, maxlen = input_str.split("-", 1)
        return (ipaddress.ip_network(network), int(maxlen))
    except ValueError:
        return (ipaddress.ip_network(input_str), None)


def set_log_level(verbosity: int) -> None:
    """Set logging verbosity."""
    level = logging.WARNING - (10 * verbosity)
    logging.basicConfig(level=level)


def main(argv: typing.Optional[ArgvType] = None) -> typing.Optional[int]:
    """Generate demo RPKI artifacts."""
    try:
        # get command line args
        if argv is None:
            argv = sys.argv[1:]
        args = parse_args(argv)
        set_log_level(args.verbosity)
        # import rpkimancer types
        log.info("setting up rpkimancer library objects")
        from ..cert import CertificateAuthority, TACertificateAuthority
        from ..sigobj import RouteOriginAttestation, RpkiGhostbusters
        # create CAs
        log.info("creating TA certificate authority")
        ta = TACertificateAuthority(as_resources=args.ta_as_resources,
                                    ip_resources=args.ta_ip_resources)
        log.info("creating suboridinate certificate authority")
        ca = CertificateAuthority(issuer=ta,
                                  as_resources=args.ca_as_resources,
                                  ip_resources=args.ca_ip_resources)
        # create ROA
        log.info("creating ROA object")
        RouteOriginAttestation(issuer=ca,
                               as_id=args.roa_asid,
                               ip_address_blocks=args.roa_networks)
        # create GBR
        log.info("creating ghostbusters record object")
        RpkiGhostbusters(issuer=ca,
                         full_name=args.gbr_full_name,
                         org=args.gbr_org,
                         email=args.gbr_email)
        # publish objects
        log.info(f"publishing in-memory objects to {args.output_dir}")
        ta.publish(pub_path=os.path.join(args.output_dir, PUB_SUB_DIR),
                   tal_path=os.path.join(args.output_dir, TAL_SUB_DIR))
    except KeyboardInterrupt:
        log.error("Interrupted by Ctrl+C")
        return 2
    except Exception as e:
        log.error(f"{e!r}", exc_info=(args.verbosity >= 3))
        return 1
    return None
