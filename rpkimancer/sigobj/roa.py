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
"""RPKI ROA implementation - RFC6482."""

from __future__ import annotations

import copy
import json
import logging
import typing

from .base import EncapsulatedContentType, SignedObject
from ..asn1.mod import RPKI_ROA
from ..resources import (AFI, IPNetwork, IPNetworkBits, IpResourcesInfo,
                         bitstring_to_net, net_to_bitstring)

log = logging.getLogger(__name__)

RoaNetworkInfo = typing.Tuple[IPNetwork, typing.Optional[int]]


class RouteOriginAttestationContentType(EncapsulatedContentType):
    """encapContentInfo for RPKI ROAs - RFC6482."""

    asn1_definition = RPKI_ROA.ct_routeOriginAuthz
    file_ext = "roa"
    as_resources = None

    def __init__(self, *,
                 version: int = 0,
                 as_id: int,
                 ip_address_blocks: typing.List[RoaNetworkInfo]) -> None:
        """Initialise the encapContentInfo."""
        log.info(f"preparing data for {self}")
        entry_type = typing.Dict[str, typing.Union[IPNetworkBits, int]]

        def address_entry(network: IPNetwork,
                          maxlen: typing.Optional[int] = None) -> entry_type:
            entry: entry_type = {"address": net_to_bitstring(network)}
            if maxlen is not None:
                entry["maxLength"] = maxlen
            return entry

        address_blocks = [{"addressFamily": AFI[network.version],
                           "addresses": [address_entry(network, maxlen)]}
                          for network, maxlen in ip_address_blocks]
        data = {"version": version,
                "asID": as_id,
                "ipAddrBlocks": address_blocks}
        super().__init__(data)
        self._ip_resources = [network for network, _ in ip_address_blocks]

    @property
    def ip_resources(self) -> IpResourcesInfo:
        """Get the IP Address Resources covered by this ROA."""
        return self._ip_resources

    def to_txt(self) -> str:
        """Get default text serialization."""
        return self.to_json()

    def to_json(self) -> str:
        """Serialize as JSON."""
        data = copy.deepcopy(self.content_data)
        afi_bytes_version_map = {v: k for k, v in AFI.items()}
        for i, addr_block in enumerate(self.content_data["ipAddrBlocks"]):
            data_addr_block = data["ipAddrBlocks"][i]
            version = afi_bytes_version_map[addr_block["addressFamily"]]
            data_addr_block["addressFamily"] = f"ipv{version}"
            for j, addr in enumerate(addr_block["addresses"]):
                data_addr = data_addr_block["addresses"][j]
                network = bitstring_to_net(addr["address"], version)
                data_addr["address"] = str(network)
        return json.dumps(data, indent=2)


class RouteOriginAttestation(SignedObject[RouteOriginAttestationContentType]):
    """CMS ASN.1 ContentInfo for RPKI ROAs."""
