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
"""Base classes for RPKI Signed Object implementations - RFC6488."""

from __future__ import annotations

import typing

from ..algorithms import DIGEST_ALGORITHMS, SHA256
from ..asn1 import Content, PKIXAlgs_2009
from ..asn1.types import OID
from ..cms import ContentInfo, SignedAttributes, SignedData
from ..resources import AsResourcesInfo, IpResourcesInfo

if typing.TYPE_CHECKING:
    from ..cert import CertificateAuthority

CMS_VERSION: typing.Final = 3


class EncapsulatedContent(Content):
    """Base class for encapContentInfo in RPKI Signed Objects - RFC6488."""

    digest_algorithm = DIGEST_ALGORITHMS[SHA256]
    content_type: OID
    file_ext: str

    @property
    def as_resources(self) -> typing.Optional[AsResourcesInfo]:
        """Get the AS Number Resources required by this eContent."""
        raise NotImplementedError

    @property
    def ip_resources(self) -> typing.Optional[IpResourcesInfo]:
        """Get the IP Address Resources required by this eContent."""
        raise NotImplementedError

    def digest(self) -> bytes:
        """Calculate the message digest over the DER-encoded eContent."""
        return self.digest_algorithm(self.to_der()).digest()  # type: ignore[call-arg, arg-type, misc] # noqa: E501

    def signed_attrs(self) -> SignedAttributes:
        """Construct the signedAttrs value from the encapContentInfo."""
        return SignedAttributes(content_type=self.content_type,
                                message_digest=self.digest())

    def signed_attrs_digest(self) -> str:
        """Calculate the message digest over the DER-encoded signedAttrs."""
        return self.digest_algorithm(self.signed_attrs().to_der()).hexdigest()  # type: ignore[call-arg, arg-type, misc] # noqa: E501


class SignedObject(ContentInfo):
    """Base CMS ASN.1 ContentInfo for RPKI Signed Objects - RFC5911/RFC6488."""

    econtent_cls: typing.Type[EncapsulatedContent]

    def __init__(self,
                 issuer: CertificateAuthority,
                 file_name: typing.Optional[str] = None,
                 *args: typing.Any,
                 **kwargs: typing.Any) -> None:
        """Initialise the SignedObject."""
        # set object file name
        self._file_name = file_name
        # construct econtent
        self._econtent = self.econtent_cls(*args, **kwargs)
        # construct certificate
        from ..cert import EECertificate
        ee_cert = EECertificate(signed_object=self,
                                issuer=issuer,
                                as_resources=self.econtent.as_resources,
                                ip_resources=self.econtent.ip_resources)
        # construct signedAttrs
        signed_attrs = self.econtent.signed_attrs()
        # construct signature
        signature = ee_cert.sign_object()

        data = {
            # rfc6488 section 2.1.1
            "version": CMS_VERSION,
            # rfc6488 section 2.1.2 and rfc7935
            "digestAlgorithms": [{"algorithm": SHA256}],
            # rfc6488 section 2.1.3
            "encapContentInfo": {
                # rfc6488 section 2.1.3.1
                "eContentType": self.econtent.content_type.get_val(),
                # rfc6488 section 2.1.3.2
                "eContent": self.econtent.to_der(),
            },
            # rfc6488 section 2.1.4
            "certificates": [
                ("certificate", ee_cert.asn1_cert.content_data),
            ],
            # 'crls' omitted per rfc6488 section 2.1.5
            # rfc6488 section 2.1.6
            "signerInfos": [
                {
                    # rfc6488 section 2.1.6.1
                    "version": CMS_VERSION,
                    # rfc6488 section 2.1.6.2
                    "sid": ("subjectKeyIdentifier", ee_cert.ski_digest),
                    # rfc6488 section 2.1.6.3
                    "digestAlgorithm": {"algorithm": SHA256},
                    # rfc6488 section 2.1.6.4
                    "signedAttrs": signed_attrs.content_data,
                    # rfc6488 section 2.1.6.5 and rfc7935
                    "signatureAlgorithm": {
                        "algorithm": PKIXAlgs_2009.rsaEncryption.get_val(),
                    },
                    # rfc6488 section 2.1.6.6
                    "signature": signature,
                    # 'unsignedAttrs' omitted per rfc6488 section 2.1.6.7
                },
            ],
        }
        super().__init__(content=SignedData(data))

    @property
    def econtent(self) -> EncapsulatedContent:
        """Get the Signed Object's encapContentInfo."""
        return self._econtent

    @property
    def file_name(self) -> str:
        """Construct the file name of the SignedObject."""
        if self._file_name is None:
            return f"{self.econtent.signed_attrs_digest()}.{self.econtent.file_ext}"  # noqa: E501
        else:
            return self._file_name
