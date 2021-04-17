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
"""Number resource ASN.1 type helpers."""

from __future__ import annotations

import ipaddress
import logging
import typing

from .asn1 import Content
from .asn1.mod import IPAddrAndASCertExtn

log = logging.getLogger(__name__)

AFI = {4: (1).to_bytes(2, "big"),
       6: (2).to_bytes(2, "big")}

Inherit = typing.Literal["INHERIT"]
AfiInfo = typing.Literal[4, 6]

_INHERIT: Inherit = "INHERIT"
INHERIT_AS = _INHERIT
INHERIT_IPV4: typing.Tuple[AfiInfo, Inherit] = (4, _INHERIT)
INHERIT_IPV6: typing.Tuple[AfiInfo, Inherit] = (6, _INHERIT)

IPNetwork = typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPNetworkBits = typing.Tuple[int, int]
IPAddressFamilyInfo = typing.Union[typing.Tuple[AfiInfo, Inherit],
                                   IPNetwork]
IpResourcesInfo = typing.Iterable[IPAddressFamilyInfo]
ASIdOrRangeInfo = typing.Union[int, typing.Tuple[int, int]]
AsResourcesInfo = typing.Union[Inherit,
                               typing.Iterable[ASIdOrRangeInfo]]


def net_to_bitstring(network: IPNetwork) -> IPNetworkBits:
    """Convert an IPNetwork to an ASN.1 BIT STRING representation."""
    netbits = network.prefixlen
    hostbits = network.max_prefixlen - netbits
    value = int(network.network_address) >> hostbits
    return (value, netbits)


class SeqOfIPAddressFamily(Content):
    """Base class for ASN.1 SEQUENCE OF IPAddressFamily types."""

    def __init__(self, ip_resources: IpResourcesInfo) -> None:
        """Initialise instance from python data."""
        net_data_type = typing.Union[Inherit,
                                     typing.Tuple[str, IPNetworkBits]]
        entry_type = typing.Tuple[int, net_data_type]

        def _net_entry(network: IPAddressFamilyInfo) -> entry_type:
            if isinstance(network, (ipaddress.IPv4Network,
                                    ipaddress.IPv6Network)):
                return network.version, ("addressPrefix",
                                         net_to_bitstring(network))
            else:
                return network[0], _INHERIT

        combined_type = typing.Tuple[str,
                                     typing.Union[typing.Literal[0],
                                                  typing.List[net_data_type]]]

        def _combine(entries: typing.List[net_data_type]) -> combined_type:
            if any(entry == _INHERIT for entry in entries):
                return ("inherit", 0)
            else:
                return ("addressesOrRanges", [entry for entry in entries])

        by_afi = {afi_data: [net_data
                             for net_version, net_data
                             in map(_net_entry, ip_resources)
                             if net_version == afi_version]
                  for (afi_version, afi_data) in AFI.items()}
        data = [{"addressFamily": afi, "ipAddressChoice": _combine(entries)}
                for afi, entries in by_afi.items() if entries]
        super().__init__(data)


class IPAddrBlocks(SeqOfIPAddressFamily):
    """ASN.1 IPAddrBlocks type - RFC3779."""

    content_syntax = IPAddrAndASCertExtn.IPAddrBlocks


class ASIdOrRange(Content):
    """ASN.1 ASIdOrRange type - RFC3779."""

    content_syntax = IPAddrAndASCertExtn.ASIdOrRange

    def __init__(self, a: ASIdOrRangeInfo) -> None:
        """Initialise instance from python data."""
        data: typing.Union[typing.Tuple[str, int],
                           typing.Tuple[str, typing.Dict[str, int]]]
        if isinstance(a, int):
            data = ("id", a)
        elif isinstance(a, tuple):
            data = ("range", {"min": a[0], "max": a[1]})
        super().__init__(data)


class ASIdentifiers(Content):
    """ASN.1 ASIdentifiers type - RFC3779."""

    content_syntax = IPAddrAndASCertExtn.ASIdentifiers

    def __init__(self, as_resources: AsResourcesInfo) -> None:
        """Initialise instance from python data."""
        asnum: typing.Union[typing.Tuple[str, int],
                            typing.Tuple[str, typing.List[typing.Any]]]
        if as_resources == INHERIT_AS:
            asnum = ("inherit", 0)
        elif isinstance(as_resources, list):
            asnum = ("asIdsOrRanges",
                     [ASIdOrRange(a).content_data for a in as_resources])
        else:
            raise ValueError
        data = {"asnum": asnum}
        super().__init__(data)
