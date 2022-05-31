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
"""rpkincant cli argument helpers."""

from __future__ import annotations

import ipaddress
import typing

if typing.TYPE_CHECKING:
    from ..resources import IPAddressFamilyInfo
    from ..sigobj.roa import RoaNetworkInfo


def ip_resource(input_str: str) -> IPAddressFamilyInfo:
    """Convert input string to IPAddressFamilyInfo variant."""
    try:
        return ipaddress.ip_network(input_str)
    except ValueError:
        lower, upper = input_str.split("-", 1)
    try:
        return ipaddress.IPv4Address(lower), ipaddress.IPv4Address(upper)
    except ValueError:
        return ipaddress.IPv6Address(lower), ipaddress.IPv6Address(upper)


def roa_network(input_str: str) -> RoaNetworkInfo:
    """Convert input string to RoaNetworkInfo tuple."""
    try:
        network, maxlen = input_str.split("-", 1)
        return (ipaddress.ip_network(network), int(maxlen))
    except ValueError:
        return (ipaddress.ip_network(input_str), None)
