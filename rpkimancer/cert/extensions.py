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
"""Number Resource Extension implementations - RFC3779."""
from __future__ import annotations

from cryptography import x509

from .oid import AS_RESOURCES_OID, IP_RESOURCES_OID
from ..resources import (ASIdentifiers, AsResourcesInfo,
                         IPAddrBlocks, IpResourcesInfo)


class IpResources(x509.UnrecognizedExtension):
    """IP Address Resources X.509 certificate extension - RFC3779."""

    # TODO: IPAddressRange support
    def __init__(self, ip_resources: IpResourcesInfo):
        """Initialise the certificate extension."""
        ip_address_blocks_data = IPAddrBlocks(ip_resources).to_der()
        super().__init__(IP_RESOURCES_OID, ip_address_blocks_data)


class AsResources(x509.UnrecognizedExtension):
    """AS Number Resources X.509 certificate extension - RFC3779."""

    def __init__(self, as_resources: AsResourcesInfo):
        """Initialise the certificate extension."""
        as_identifiers_data = ASIdentifiers(as_resources).to_der()
        super().__init__(AS_RESOURCES_OID, as_identifiers_data)
