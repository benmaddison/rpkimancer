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

import logging
import typing

from cryptography import x509

from . import asn1, oid
from ..asn1.mod import IPAddrAndASCertExtn
from ..asn1.types import ASN1Class
from ..resources import (ASIdentifiers, AsResourcesInfo,
                         IPAddrBlocks, IpResourcesInfo)

log = logging.getLogger(__name__)


class X509CertificateExtension(x509.UnrecognizedExtension):
    """Custom certificate extension with ASN.1 handling."""

    @classmethod
    def __init_subclass__(cls,
                          ext_type: typing.Optional[ASN1Class] = None,
                          **kwargs: typing.Any) -> None:
        """Register the EXTENSION instance for DER encoding/decoding."""
        super().__init_subclass__(**kwargs)
        if ext_type is not None:
            asn1.Certificate.register_ext_type(ext_type)


class IpResources(X509CertificateExtension,
                  ext_type=IPAddrAndASCertExtn.ext_IPAddrBlocks):
    """IP Address Resources X.509 certificate extension - RFC3779."""

    def __init__(self, ip_resources: IpResourcesInfo) -> None:
        """Initialise the certificate extension."""
        ip_address_blocks_data = IPAddrBlocks(ip_resources).to_der()
        super().__init__(oid.IP_RESOURCES_OID, ip_address_blocks_data)


class AsResources(X509CertificateExtension,
                  ext_type=IPAddrAndASCertExtn.ext_ASIdentifiers):
    """AS Number Resources X.509 certificate extension - RFC3779."""

    def __init__(self, as_resources: AsResourcesInfo) -> None:
        """Initialise the certificate extension."""
        as_identifiers_data = ASIdentifiers(as_resources).to_der()
        super().__init__(oid.AS_RESOURCES_OID, as_identifiers_data)
