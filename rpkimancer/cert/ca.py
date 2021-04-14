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

import base64
import datetime
import os
import typing

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .base import BaseResourceCertificate, ResourceCertificateList
from .oid import AIA_CA_ISSUERS_OID, SIA_CA_REPOSITORY_OID, SIA_MFT_ACCESS_OID
from ..sigobj import RpkiManifest


class CertificateAuthority(BaseResourceCertificate):
    def __init__(self, *,
                 common_name: str = "CA",
                 crl_days: int = 7,
                 mft_days: int = 7,
                 **kwargs) -> None:
        self._issued: typing.List[BaseResourceCertificate] = list()
        self.next_serial_number = 1
        super().__init__(common_name=common_name, ca=True, **kwargs)
        # rfc 6487 section 5
        self._crl: typing.Optional[x509.CertificateRevocationList] = None
        self.crl_days = crl_days
        self.next_crl_number = 0
        self.issue_crl()
        self.mft_days = mft_days
        self.next_mft_number = 0

    @property
    def crl(self):
        return self._crl

    @property
    def crl_der(self):
        return self.crl.public_bytes(serialization.Encoding.DER)

    @property
    def repo_path(self):
        return os.path.join(self.issuer.repo_path, self.subject_cn)

    @property
    def cert_path(self):
        return os.path.join(self.issuer.repo_path, f"{self.subject_cn}.cer")

    @property
    def crl_path(self):
        return os.path.join(self.repo_path, "revoked.crl")

    @property
    def mft_path(self):
        return os.path.join(self.repo_path, "manifest.mft")

    @property
    def issued(self):
        for cert in self._issued:
            yield cert

    @property
    def crldp(self):
        crldp_uri = f"{self.base_uri}/{self.crl_path}"
        crldp = x509.CRLDistributionPoints([
            x509.DistributionPoint([x509.UniformResourceIdentifier(crldp_uri)],
                                   relative_name=None,
                                   reasons=None,
                                   crl_issuer=None)
        ])
        return crldp

    @property
    def aia(self):
        aia_uri = f"{self.base_uri}/{self.cert_path}"
        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(AIA_CA_ISSUERS_OID,
                                   x509.UniformResourceIdentifier(aia_uri))
        ])
        return aia

    @property
    def sia(self):
        sia_repo_uri = f"{self.base_uri}/{self.repo_path}"
        sia_mft_uri = f"{self.base_uri}/{self.mft_path}"
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(SIA_CA_REPOSITORY_OID,
                                   x509.UniformResourceIdentifier(sia_repo_uri)),  # noqa: E501
            x509.AccessDescription(SIA_MFT_ACCESS_OID,
                                   x509.UniformResourceIdentifier(sia_mft_uri))
        ])
        return sia

    def issue_cert(self, subject: BaseResourceCertificate = None):
        if subject is None:
            subject = self
        cert = subject.cert_builder.sign(private_key=self.private_key,
                                         algorithm=self.HASH_ALGORITHM)
        self._issued.append(subject)
        self.next_serial_number += 1
        return cert

    def issue_crl(self, to_revoke: ResourceCertificateList = None):
        now = datetime.datetime.utcnow()
        next_update = now + datetime.timedelta(days=self.crl_days)
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(self.cert.subject)
        crl_builder = crl_builder.last_update(now)
        crl_builder = crl_builder.next_update(next_update)
        aki = x509.AuthorityKeyIdentifier\
                  .from_issuer_public_key(self.public_key)
        crl_builder = crl_builder.add_extension(aki, critical=False)
        crl_number = x509.CRLNumber(self.next_crl_number)
        crl_builder = crl_builder.add_extension(crl_number, critical=False)
        if self.crl is not None:
            for revoked in self.crl:
                # TODO: clean up expired certs
                crl_builder = crl_builder.add_revoked_certificate(revoked)
        if to_revoke is not None:
            for c in to_revoke:
                serial_number = c.cert.serial_number
                rc_builder = x509.RevokedCertificateBuilder(serial_number, now)
                revoked_cert = rc_builder.build()
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
        self._crl = crl_builder.sign(self.private_key, self.HASH_ALGORITHM)
        self.next_crl_number += 1

    def issue_mft(self, file_list):
        now = datetime.datetime.utcnow()
        next_update = now + datetime.timedelta(days=self.mft_days)
        self._mft = RpkiManifest(issuer=self,
                                 file_name=os.path.basename(self.mft_path),
                                 manifest_number=self.next_mft_number,
                                 this_update=now,
                                 next_update=next_update,
                                 file_list=file_list)
        self.next_mft_number += 1

    @property
    def mft(self):
        return self._mft

    def publish(self, pub_path, recursive=True):
        mft_file_list = list()
        full_pub_path = os.path.join(pub_path, self.uri_path)
        os.makedirs(os.path.join(full_pub_path, self.repo_path), exist_ok=True)
        with open(os.path.join(full_pub_path, self.cert_path), "wb") as f:
            f.write(self.cert_der)
        with open(os.path.join(full_pub_path, self.crl_path), "wb") as f:
            f.write(self.crl_der)
        mft_file_list.append((os.path.basename(self.crl_path),
                              self.crl_der))
        for issuee in self.issued:
            if issuee is not self:
                mft_file_list.append(issuee.mft_entry)
                if recursive is True:
                    issuee.publish(pub_path, recursive=recursive)
        self.issue_mft(mft_file_list)
        with open(os.path.join(full_pub_path, self.mft_path), "wb") as f:
            f.write(self.mft.to_der())


class TACertificateAuthority(CertificateAuthority):
    def __init__(self, *,
                 common_name: str = "TA",
                 base_uri: str = "rsync://rpki.example.net/rpki",
                 **kwargs) -> None:
        super().__init__(common_name=common_name, issuer=None, **kwargs)

    @property
    def repo_path(self):
        return self.subject_cn

    @property
    def cert_path(self):
        return f"{self.subject_cn}.cer"

    @property
    def tal_path(self):
        return f"{self.subject_cn}.tal"

    @property
    def tal(self):
        tal_contents = f"{self.base_uri}/{self.cert_path}\n\n".encode()
        tal_contents += base64.b64encode(self.subject_public_key_info.to_der())
        return tal_contents

    def publish(self, pub_path, tal_path, recursive=True):
        super().publish(pub_path, recursive=recursive)
        os.makedirs(tal_path, exist_ok=True)
        with open(os.path.join(tal_path, self.tal_path), "wb") as f:
            f.write(self.tal)
