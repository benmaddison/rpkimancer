import ipaddress
import typing

from .asn1 import IPAddrAndASCertExtn
from .cms import Content

AFI = {4: (1).to_bytes(2, "big"),
       6: (2).to_bytes(2, "big")}

IpResourcesInfo = typing.List[ipaddress.ip_network]
ASIdOrRangeInfo = typing.Union[int, typing.Tuple[int, int]]
AsResourcesInfo = typing.List[ASIdOrRangeInfo]


class IPAddressFamily(Content):

    content_syntax = IPAddrAndASCertExtn.IPAddressFamily

    def __init__(self, network: ipaddress.ip_network):
        netbits = network.prefixlen
        hostbits = network.max_prefixlen - netbits
        value = int(network.network_address) >> hostbits
        data = {"addressFamily": AFI[network.version],
                "ipAddressChoice": ("addressesOrRanges",
                                    [("addressPrefix", (value, netbits))])}
        super().__init__(data)


class IPAddrBlocks(Content):

    content_syntax = IPAddrAndASCertExtn.IPAddrBlocks

    def __init__(self, ip_resources: IpResourcesInfo):
        data = [IPAddressFamily(n).content_data for n in ip_resources]
        super().__init__(data)


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
        data = {"asnum": ("asIdsOrRanges",
                          [ASIdOrRange(a).content_data for a in as_resources])}
        super().__init__(data)
