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
import ipaddress
import typing

from .asn1 import IPAddrAndASCertExtn
from .cms import Content

AFI = {4: (1).to_bytes(2, "big"),
       6: (2).to_bytes(2, "big")}

_INHERIT = "INHERIT"
INHERIT_AS = _INHERIT
INHERIT_IPV4 = (4, _INHERIT)
INHERIT_IPV6 = (6, _INHERIT)

AfiInfo = typing.Literal[4, 6]
Inherit = typing.Literal[_INHERIT]
IPNetwork = typing.Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddressFamilyInfo = typing.Union[typing.Tuple[AfiInfo, Inherit],
                                   IPNetwork]
IpResourcesInfo = typing.List[IPAddressFamilyInfo]
ASIdOrRangeInfo = typing.Union[int, typing.Tuple[int, int]]
AsResourcesInfo = typing.Union[Inherit,
                               typing.List[ASIdOrRangeInfo]]


def net_to_bitstring(network: IPNetwork) -> typing.Tuple[int, int]:
    netbits = network.prefixlen
    hostbits = network.max_prefixlen - netbits
    value = int(network.network_address) >> hostbits
    return (value, netbits)


class SeqOfIPAddressFamily(Content):

    def __init__(self, ip_resources: IpResourcesInfo):
        def data(network: IPAddressFamilyInfo):
            if isinstance(network, (ipaddress.IPv4Network,
                                    ipaddress.IPv6Network)):
                return network.version, ("addressPrefix",
                                         net_to_bitstring(network))
            else:
                return network[0], _INHERIT

        def combine(entries):
            if any(entry == _INHERIT for entry in entries):
                return ("inherit", 0)
            else:
                return ("addressesOrRanges", [entry for entry in entries])

        by_afi = {afi_data: [net_data
                             for net_version, net_data
                             in map(data, ip_resources)
                             if net_version == afi_version]
                  for (afi_version, afi_data) in AFI.items()}
        data = [{"addressFamily": afi, "ipAddressChoice": combine(entries)}
                for afi, entries in by_afi.items() if entries]
        super().__init__(data)


class IPAddrBlocks(SeqOfIPAddressFamily):

    content_syntax = IPAddrAndASCertExtn.IPAddrBlocks


class ASIdOrRange(Content):

    content_syntax = IPAddrAndASCertExtn.ASIdOrRange

    def __init__(self, a: ASIdOrRangeInfo):
        if isinstance(a, int):
            data = ("id", a)
        elif isinstance(a, tuple):
            data = ("range", {"min": a[0], "max": a[1]})
        super().__init__(data)


class ASIdentifiers(Content):

    content_syntax = IPAddrAndASCertExtn.ASIdentifiers

    def __init__(self, as_resources: AsResourcesInfo):
        if as_resources == INHERIT_AS:
            asnum = ("inherit", 0)
        else:
            asnum = ("asIdsOrRanges",
                     [ASIdOrRange(a).content_data for a in as_resources])
        data = {"asnum": asnum}
        super().__init__(data)
