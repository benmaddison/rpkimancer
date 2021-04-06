import os

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from .base import BaseResourceCertificate
from .oid import SIA_OBJ_ACCESS_OID
from ..sigobj import SignedObject


class EECertificate(BaseResourceCertificate):
    def __init__(self, signed_object: SignedObject, *args, **kwargs):
        self._signed_object = signed_object
        common_name = signed_object.econtent.signed_attrs_digest()
        super().__init__(common_name=common_name, *args, **kwargs)

    @property
    def signed_object(self):
        return self._signed_object

    @property
    def file_name(self):
        return f"{self.subject_cn}.{self.signed_object.econtent.file_ext}"

    @property
    def object_path(self):
        return os.path.join(self.issuer.repo_path, self.file_name)

    @property
    def mft_entry(self):
        return (os.path.basename(self.object_path),
                self.signed_object.to_der())

    def sia(self, base_uri):
        sia_obj_uri = f"{base_uri}/{self.object_path}"
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

    def publish(self, base_path, recursive=True):
        with open(os.path.join(base_path, self.object_path), "wb") as f:
            f.write(self.signed_object.to_der())
