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
import os
import typing

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from .base import BaseResourceCertificate, ManifestEntryInfo
from .ca import CertificateAuthority
from .oid import SIA_OBJ_ACCESS_OID

if typing.TYPE_CHECKING:
    from ..sigobj import SignedObject

log = logging.getLogger(__name__)


class EECertificate(BaseResourceCertificate):
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
    def object_path(self) -> str:
        """Get the filesystem path to the SignedObject in the issuer publication point."""  # noqa: E501
        return os.path.join(typing.cast(CertificateAuthority,
                                        self.issuer).repo_path,
                            self.signed_object.file_name)

    @property
    def mft_entry(self) -> typing.Optional[ManifestEntryInfo]:
        """Get an entry for inclusion in the issuer's manifest."""
        return (os.path.basename(self.object_path),
                self.signed_object.to_der())

    @property
    def sia(self) -> typing.Optional[x509.SubjectInformationAccess]:
        """Get the SubjectInformationAccess extension for the certificate."""
        sia_obj_uri = f"{self.base_uri}/{self.object_path}"
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(SIA_OBJ_ACCESS_OID,
                                   x509.UniformResourceIdentifier(sia_obj_uri)),  # noqa: E501
        ])
        return sia

    def sign_object(self) -> bytes:
        """Construct a signature over the signedAttrs of the SignedObject."""
        message = self.signed_object.econtent.signed_attrs().to_der()
        signature = self.private_key.sign(data=message,
                                          padding=padding.PKCS1v15(),
                                          algorithm=self.HASH_ALGORITHM)
        return signature

    def publish(self, pub_path: str, recursive: bool = True) -> None:
        """Publish the SignedObject artifact as a DER file in the PP."""
        with open(os.path.join(pub_path, self.uri_path, self.object_path),
                  "wb") as f:
            f.write(self.signed_object.to_der())
