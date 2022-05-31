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

from .asn1 import Interface
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
IPRange = typing.Union[typing.Tuple[ipaddress.IPv4Address,
                                    ipaddress.IPv4Address],
                       typing.Tuple[ipaddress.IPv6Address,
                                    ipaddress.IPv6Address]]

IPNetworkBits = typing.Tuple[int, int]
IPRangeBits = typing.Tuple[IPNetworkBits, IPNetworkBits]

IPAddressFamilyInfo = typing.Union[typing.Tuple[AfiInfo, Inherit],
                                   IPNetwork,
                                   IPRange]
IpResourcesInfo = typing.Iterable[IPAddressFamilyInfo]
ASIdOrRangeInfo = typing.Union[int, typing.Tuple[int, int]]
AsResourcesInfo = typing.Union[Inherit,
                               typing.Iterable[ASIdOrRangeInfo]]


def net_to_bitstring(network: IPNetwork) -> IPNetworkBits:
    """Convert an IPNetwork to an ASN.1 BIT STRING representation."""
    log.debug(f"converting {network} to rfc3779 bit string")
    netbits = network.prefixlen
    hostbits = network.max_prefixlen - netbits
    value = int(network.network_address) >> hostbits
    return (value, netbits)


def bitstring_to_net(bits: IPNetworkBits, version: int) -> IPNetwork:
    """Convert an ASN.1 BIT STRING representation to an IPNetwork."""
    len_map = {4: ipaddress.IPV4LENGTH, 6: ipaddress.IPV6LENGTH}
    cls_map = {4: ipaddress.IPv4Network, 6: ipaddress.IPv6Network}
    value, netbits = bits
    hostbits = len_map[version] - netbits
    cls = typing.cast(typing.Type[IPNetwork], cls_map[version])
    net = cls((value << hostbits, netbits))
    return net


class IPAddrBlocks(Interface):
    """ASN.1 IPAddrBlocks type - RFC3779."""

    content_syntax = IPAddrAndASCertExtn.IPAddrBlocks

    def __init__(self, ip_resources: IpResourcesInfo) -> None:
        """Initialise instance from python data."""
        log.info(f"preparing data for {self}")
        net_data_type = typing.Union[Inherit,
                                     typing.Tuple[str, IPNetworkBits]]
        entry_type = typing.Tuple[int, net_data_type]

        def _net_entry(data: IPAddressFamilyInfo) -> entry_type:
            if isinstance(data, (ipaddress.IPv4Network,
                                 ipaddress.IPv6Network)):
                return data.version, ("addressPrefix", net_to_bitstring(data))
            elif isinstance(data[0], (ipaddress.IPv4Address,
                                      ipaddress.IPv6Address)):
                return data[0].version, ("addressRange",
                                         IPAddressRange(data).content_data)
            else:
                return data[0], _INHERIT

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


class IPAddressRange(Interface):
    """ASN.1 IPAddressRange type - RFC3779."""

    content_syntax = IPAddrAndASCertExtn.IPAddressRange

    def __init__(self, ip_range: IPRange) -> None:
        """Initialise instance from python data."""
        # Encode per RFC3779 section 2.1.2
        (low_addr, high_addr) = ip_range
        # Lower-bound address is encoded as a BIT STRING with trailling
        # zero-bits truncated
        low_bits = int(low_addr)
        low_len: int = low_addr.max_prefixlen
        while low_bits % 2 == 0:
            low_bits = low_bits >> 1
            low_len = low_len - 1
        # Upper-bound address is encoded as a BIT STRING with trailling
        # one-bits truncated
        high_bits = int(high_addr)
        high_len: int = high_addr.max_prefixlen
        while high_bits % 2 == 1:
            high_bits = high_bits >> 1
            high_len = high_len - 1
        data = {"min": (low_bits, low_len),
                "max": (high_bits, high_len)}
        super().__init__(data)


class ASIdOrRange(Interface):
    """ASN.1 ASIdOrRange type - RFC3779."""

    content_syntax = IPAddrAndASCertExtn.ASIdOrRange

    def __init__(self, a: ASIdOrRangeInfo) -> None:
        """Initialise instance from python data."""
        log.info(f"preparing data for {self}")
        data: typing.Union[typing.Tuple[str, int],
                           typing.Tuple[str, typing.Dict[str, int]]]
        if isinstance(a, int):
            data = ("id", a)
        elif isinstance(a, tuple):
            data = ("range", {"min": a[0], "max": a[1]})
        super().__init__(data)


class ASIdentifiers(Interface):
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
        else:  # pragma: no cover
            raise ValueError
        data = {"asnum": asnum}
        super().__init__(data)
