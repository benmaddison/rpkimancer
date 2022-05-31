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

import logging
import os
import typing

from ..algorithms import DIGEST_ALGORITHMS, SHA256
from ..asn1.mod import PKIXAlgs_2009
from ..cert import EECertificate
from ..cms import (ContentInfo,
                   ContentType,
                   EncapsulatedContentInfo,
                   SignedAttributes,
                   SignedData)
from ..resources import AsResourcesInfo, IpResourcesInfo

if typing.TYPE_CHECKING:
    from ..cert import CertificateAuthority

log = logging.getLogger(__name__)

CMS_VERSION: typing.Final = 3

ECT = typing.TypeVar("ECT", bound="EncapsulatedContentType")


class EncapsulatedContentType(ContentType):
    """Base for CONTENT-TYPE instance for RPKI Signed Objects - RFC6488."""

    digest_algorithm = DIGEST_ALGORITHMS[SHA256]
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
        return self.digest_algorithm(self.to_der()).digest()  # type: ignore[call-arg, misc] # noqa: E501

    def signed_attrs(self) -> SignedAttributes:
        """Construct the signedAttrs value from the EncapsulatedContentInfo."""
        return SignedAttributes(content_type=self.content_type,
                                message_digest=self.digest())

    def signed_attrs_digest(self) -> str:
        """Calculate the message digest over the DER-encoded signedAttrs."""
        return self.digest_algorithm(self.signed_attrs().to_der()).hexdigest()  # type: ignore[call-arg, misc] # noqa: E501


class SignedObject(ContentInfo[SignedData], typing.Generic[ECT]):
    """Base CMS ASN.1 ContentInfo for RPKI Signed Objects - RFC5911/RFC6488."""

    econtent_type: typing.Type[ECT]
    ee_cert_cls: typing.Type[EECertificate[ECT]] = EECertificate[ECT]

    @classmethod
    def __init_subclass__(cls, **kwargs: typing.Any) -> None:
        """Register EncapsulatedContentInfo CONTENT-TYPE for DER encoding."""
        super().__init_subclass__(**kwargs)
        econtent_type = typing.get_args(cls.__orig_bases__[0])[0]  # type: ignore[attr-defined] # noqa: E501
        log.info(f"Adding {econtent_type} to constraining object info set")
        cls.register_econtent_type(SignedData, econtent_type)
        cls.econtent_type = econtent_type

    def __init__(self,
                 issuer: CertificateAuthority,
                 file_name: typing.Optional[str] = None,
                 *args: typing.Any,
                 **kwargs: typing.Any) -> None:
        """Initialise the SignedObject."""
        log.info(f"preparing data for {self}")
        # set object file name
        self._file_name = file_name
        # construct encapContentInfo
        self._econtent = self.econtent_type(*args, **kwargs)
        self._econtent_info = EncapsulatedContentInfo(econtent=self.econtent)
        # construct certificate
        ee_cert = self.ee_cert_cls(signed_object=self,
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
            "encapContentInfo": self.econtent_info.content_data,
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
    def econtent_info(self) -> EncapsulatedContentInfo[ECT]:
        """Get the Signed Object's encapContentInfo."""
        try:
            return self._econtent_info
        except AttributeError:
            eci = EncapsulatedContentInfo[ECT].from_content_info(self)
            self._econtent_info = eci
        return self._econtent_info

    @property
    def econtent(self) -> ECT:
        """Get the Signed Object's eContent."""
        try:
            return self._econtent
        except AttributeError:
            econtent_data = self.econtent_info.econtent_val
            self._econtent = self.econtent_type.from_data(econtent_data)
        return self._econtent

    @property
    def file_name(self) -> str:
        """Construct the file name of the SignedObject."""
        if self._file_name is None:
            return f"{self.econtent.signed_attrs_digest()}.{self.econtent.file_ext}"  # noqa: E501
        else:
            return self._file_name

    def publish(self, *,
                pub_path: str,
                uri_path: str,
                repo_path: str,
                **kwargs: typing.Any) -> None:
        """Publish the SignedObject artifact as a DER file in the PP."""
        with open(os.path.join(pub_path, uri_path, repo_path, self.file_name),
                  "wb") as f:
            f.write(self.to_der())
