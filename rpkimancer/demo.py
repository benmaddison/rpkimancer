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
"""Demo script to show rpkimancer library usage."""

from __future__ import annotations

import argparse
import ipaddress
import os

from .cert import CertificateAuthority, TACertificateAuthority
from .sigobj import RouteOriginAttestation, RpkiGhostbusters

DEMO_ASN = 37271
DEMO_BASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                              "target", "demo")
PUB_PATH = os.path.join(DEMO_BASE_PATH, "repo")
TAL_PATH = os.path.join(DEMO_BASE_PATH, "tals")


def demo():
    """Run the demo."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--asn", default=DEMO_ASN,
                        help="ASN to include in resources")
    args = parser.parse_args()
    # create CAs
    ta_resources = {"ip_resources": [ipaddress.ip_network("0.0.0.0/0"),
                                     ipaddress.ip_network("::/0")],
                    "as_resources": [(0, 4294967295)]}
    ta = TACertificateAuthority(**ta_resources)
    ca_resources = {"ip_resources": [ipaddress.ip_network("41.78.188.0/22"),
                                     ipaddress.ip_network("197.157.64.0/19")],
                    "as_resources": [37271]}
    ca = CertificateAuthority(issuer=ta, **ca_resources)
    # create ROA
    RouteOriginAttestation(issuer=ca,
                           as_id=args.asn,
                           ip_address_blocks=[(ipaddress.ip_network("41.78.188.0/22"),  # noqa: E501
                                               None),
                                              (ipaddress.ip_network("197.157.64.0/19"),  # noqa: E501
                                               24)])
    # create GBR
    RpkiGhostbusters(issuer=ca,
                     full_name="Workonline Network Operations Center",
                     org="Workonline Communications",
                     email="noc@workonline.africa")
    # publish objects
    ta.publish(pub_path=PUB_PATH, tal_path=TAL_PATH)


if __name__ == "__main__":
    demo()
