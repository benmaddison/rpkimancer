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
from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from .base import BaseResourceCertificate
from .oid import SIA_OBJ_ACCESS_OID
from ..sigobj import SignedObject


class EECertificate(BaseResourceCertificate):
    def __init__(self, *, signed_object: SignedObject, **kwargs):
        self._signed_object = signed_object
        common_name = signed_object.econtent.signed_attrs_digest()
        super().__init__(common_name=common_name, **kwargs)

    @property
    def signed_object(self):
        return self._signed_object

    @property
    def object_path(self):
        return os.path.join(self.issuer.repo_path,
                            self.signed_object.file_name)

    @property
    def mft_entry(self):
        return (os.path.basename(self.object_path),
                self.signed_object.to_der())

    @property
    def sia(self):
        sia_obj_uri = f"{self.base_uri}/{self.object_path}"
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(SIA_OBJ_ACCESS_OID,
                                   x509.UniformResourceIdentifier(sia_obj_uri))
        ])
        return sia

    def sign_object(self):
        message = self.signed_object.econtent.signed_attrs().to_der()
        signature = self.private_key.sign(data=message,
                                          padding=padding.PKCS1v15(),
                                          algorithm=self.HASH_ALGORITHM)
        return signature

    def publish(self, pub_path, recursive=True):
        with open(os.path.join(pub_path, self.uri_path, self.object_path),
                  "wb") as f:
            f.write(self.signed_object.to_der())
