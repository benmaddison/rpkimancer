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
import typing

from .base import EncapsulatedContent, SignedObject
from ..asn1 import RPKI_ROA
from ..resources import AFI, IPNetwork, net_to_bitstring


class RouteOriginAttestationEContent(EncapsulatedContent):

    content_type = RPKI_ROA.id_ct_routeOriginAuthz
    content_syntax = RPKI_ROA.RouteOriginAttestation
    file_ext = "roa"

    _ip_address_blocks_type = typing.List[typing.Tuple[IPNetwork,
                                                       typing.Optional[int]]]

    def __init__(self,
                 version: int = 0,
                 as_id: int = None,
                 ip_address_blocks: _ip_address_blocks_type = None):

        def address_entry(network: IPNetwork, maxlen: int):
            entry = {"address": net_to_bitstring(network)}
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
        self.ip_resources = [network for network, _ in ip_address_blocks]


class RouteOriginAttestation(SignedObject):

    econtent_cls = RouteOriginAttestationEContent
