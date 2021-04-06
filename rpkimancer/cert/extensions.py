from cryptography import x509

from .oid import AS_RESOURCES_OID, IP_RESOURCES_OID
from ..resources import (ASIdentifiers, AsResourcesInfo,
                         IPAddrBlocks, IpResourcesInfo)


class IpResources(x509.UnrecognizedExtension):
    # TODO: IPAddressRange and inherit support
    def __init__(self, ip_resources: IpResourcesInfo):
        ip_address_blocks_data = IPAddrBlocks(ip_resources).to_der()
        super().__init__(IP_RESOURCES_OID, ip_address_blocks_data)


class AsResources(x509.UnrecognizedExtension):
    # TODO: inherit support
    def __init__(self, as_resources: AsResourcesInfo):
        as_identifiers_data = ASIdentifiers(as_resources).to_der()
        super().__init__(AS_RESOURCES_OID, as_identifiers_data)
