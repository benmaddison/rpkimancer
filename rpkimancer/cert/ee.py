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
"""RPKI EE Certificate implementation - RFC6487."""

from __future__ import annotations

import logging
import typing

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from . import base, ca, oid

if typing.TYPE_CHECKING:
    from ..sigobj import SignedObject

log = logging.getLogger(__name__)


class EECertificate(base.BaseResourceCertificate):
    """RPKI EE Certificate - RFC6487."""

    def __init__(self, *,
                 signed_object: SignedObject,
                 **kwargs: typing.Any) -> None:
        """Initialise the EE Certificate."""
        self._signed_object = signed_object
        common_name = signed_object.econtent.signed_attrs_digest()
        super().__init__(common_name=common_name, **kwargs)

    @property
    def signed_object(self) -> SignedObject:
        """Get the SignedObject that this certificate signs."""
        return self._signed_object

    @property
    def issuer_repo_path(self) -> str:
        """Get the filesystem path to the the issuer publication point."""
        return typing.cast(ca.CertificateAuthority, self.issuer).repo_path

    @property
    def mft_entry(self) -> typing.Optional[base.ManifestEntryInfo]:
        """Get an entry for inclusion in the issuer's manifest."""
        return (self.signed_object.file_name,
                self.signed_object.to_der())

    @property
    def sia(self) -> typing.Optional[x509.SubjectInformationAccess]:
        """Get the SubjectInformationAccess extension for the certificate."""
        sia_obj_uri = f"{self.base_uri}/" \
                      f"{self.issuer_repo_path}/" \
                      f"{self.signed_object.file_name}"
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(oid.SIA_OBJ_ACCESS_OID,
                                   x509.UniformResourceIdentifier(sia_obj_uri)),  # noqa: E501
        ])
        return sia

    def sign_object(self) -> bytes:
        """Construct a signature over the signedAttrs of the SignedObject."""
        message = self.signed_object.econtent.signed_attrs().to_der()
        signature = self.private_key.sign(data=message,
                                          padding=padding.PKCS1v15(),
                                          algorithm=self.hash_algorithm())
        return signature

    def publish(self, *, pub_path: str, **kwargs: typing.Any) -> None:
        """Publish the SignedObject artifact as a DER file in the PP."""
        self.signed_object.publish(pub_path=pub_path,
                                   uri_path=self.uri_path,
                                   repo_path=self.issuer_repo_path,
                                   **kwargs)
