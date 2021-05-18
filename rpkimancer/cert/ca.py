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
"""RPKI Certificate Authority implementation - RFC6487."""

from __future__ import annotations

import base64
import datetime
import logging
import os
import typing

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import base, oid

if typing.TYPE_CHECKING:
    from ..sigobj import RpkiManifest

log = logging.getLogger(__name__)


class CertificateAuthority(base.BaseResourceCertificate):
    """RPKI Certificate Authority - RFC6487."""

    def __init__(self, *,
                 common_name: str = "CA",
                 crl_days: int = 7,
                 mft_days: int = 7,
                 **kwargs: typing.Any) -> None:
        """Initialise the Certificate Authority."""
        log.info(f"doing initialisation of {self} as CertificateAuthority")
        self._issued: base.ResourceCertificateList = list()
        self.next_serial_number = 1
        super().__init__(common_name=common_name, ca=True, **kwargs)
        # rfc 6487 section 5
        self.crl_days = crl_days
        self.next_crl_number = 0
        self._crl: typing.Optional[x509.CertificateRevocationList] = None
        self.issue_crl()
        self.mft_days = mft_days
        self.next_mft_number = 0

    @property
    def crl(self) -> typing.Optional[x509.CertificateRevocationList]:
        """Get the last CRL issued by this CA."""
        return self._crl

    @property
    def crl_der(self) -> bytes:
        """Get the last CRL as DER-encoded bytes."""
        return typing.cast(x509.CertificateRevocationList,
                           self.crl).public_bytes(serialization.Encoding.DER)

    @property
    def repo_path(self) -> str:
        """Get the filesystem path to this CA's publication point."""
        return os.path.join(typing.cast(CertificateAuthority,
                                        self.issuer).repo_path,
                            self.subject_cn)

    @property
    def cert_path(self) -> str:
        """Get the filesystem path to cert in the issuer publication point."""
        return os.path.join(typing.cast(CertificateAuthority,
                                        self.issuer).repo_path,
                            f"{self.subject_cn}.cer")

    @property
    def mft_entry(self) -> typing.Optional[base.ManifestEntryInfo]:
        """Get an entry for inclusion in the issuer's manifest."""
        return (os.path.basename(self.cert_path), self.cert_der)

    @property
    def crl_path(self) -> str:
        """Get the filesystem path to the CRL in publication point."""
        return os.path.join(self.repo_path, "revoked.crl")

    @property
    def mft_path(self) -> str:
        """Get the filesystem path to the manifest in publication point."""
        return os.path.join(self.repo_path, "manifest.mft")

    @property
    def issued(self) -> base.ResourceCertificates:
        """Get a generator over the certifactes issued by this CA."""
        for cert in self._issued:
            yield cert

    @property
    def crldp(self) -> typing.Optional[x509.CRLDistributionPoints]:
        """Get the CRLDistributionPoint extension for the certificate."""
        crldp_uri = f"{self.base_uri}/{self.crl_path}"
        crldp = x509.CRLDistributionPoints([
            x509.DistributionPoint([x509.UniformResourceIdentifier(crldp_uri)],
                                   relative_name=None,
                                   reasons=None,
                                   crl_issuer=None),
        ])
        return crldp

    @property
    def aia(self) -> typing.Optional[x509.AuthorityInformationAccess]:
        """Get the AuthorityInformationAccess extension for the certificate."""
        aia_uri = f"{self.base_uri}/{self.cert_path}"
        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(oid.AIA_CA_ISSUERS_OID,
                                   x509.UniformResourceIdentifier(aia_uri)),
        ])
        return aia

    @property
    def sia(self) -> typing.Optional[x509.SubjectInformationAccess]:
        """Get the SubjectInformationAccess extension for the certificate."""
        sia_repo_uri = f"{self.base_uri}/{self.repo_path}"
        sia_mft_uri = f"{self.base_uri}/{self.mft_path}"
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(oid.SIA_CA_REPOSITORY_OID,
                                   x509.UniformResourceIdentifier(sia_repo_uri)),  # noqa: E501
            x509.AccessDescription(oid.SIA_MFT_ACCESS_OID,
                                   x509.UniformResourceIdentifier(sia_mft_uri)),  # noqa: E501
        ])
        return sia

    def issue_cert(self,
                   subject: typing.Optional[base.BaseResourceCertificate] = None) -> x509.Certificate:  # noqa: E501
        """Issue a new Resource Certificate with this CA."""
        if subject is None:
            subject = self
        cert = subject.cert_builder.sign(private_key=self.private_key,
                                         algorithm=self.hash_algorithm())
        self._issued.append(subject)
        self.next_serial_number += 1
        return cert

    def issue_crl(self,
                  to_revoke: typing.Optional[base.ResourceCertificates] = None) -> None:  # noqa: E501
        """Issue a new CRL for this CA."""
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
            for revoked in self.crl:  # type: ignore[attr-defined]
                # TODO: clean up expired certs
                crl_builder = crl_builder.add_revoked_certificate(revoked)
        if to_revoke is not None:
            for c in to_revoke:
                rc_builder = x509.RevokedCertificateBuilder()
                rc_builder = rc_builder.revocation_date(now)
                rc_builder = rc_builder.serial_number(c.cert.serial_number)
                revoked_cert = rc_builder.build()
                crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
        self._crl = crl_builder.sign(self.private_key, self.hash_algorithm())
        self.next_crl_number += 1

    def issue_mft(self,
                  file_list: typing.List[base.ManifestEntryInfo]) -> None:
        """Issue a new manifest for this CA."""
        now = datetime.datetime.utcnow()
        next_update = now + datetime.timedelta(days=self.mft_days)
        from ..sigobj import RpkiManifest
        self._mft = RpkiManifest(issuer=self,
                                 file_name=os.path.basename(self.mft_path),
                                 manifest_number=self.next_mft_number,
                                 this_update=now,
                                 next_update=next_update,
                                 file_list=file_list)
        self.next_mft_number += 1

    @property
    def mft(self) -> RpkiManifest:
        """Get the last manifest issued by this CA."""
        return self._mft

    def publish(self, *,
                pub_path: str,
                recursive: bool = True,
                **kwargs: typing.Any) -> None:
        """Publish this CA's artifacts as DER files in the PP."""
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
                if issuee.mft_entry is not None:
                    mft_file_list.append(issuee.mft_entry)
                if recursive is True:
                    issuee.publish(pub_path=pub_path,
                                   recursive=recursive,
                                   **kwargs)
        self.issue_mft(mft_file_list)
        with open(os.path.join(full_pub_path, self.mft_path), "wb") as f:
            f.write(self.mft.to_der())


class TACertificateAuthority(CertificateAuthority):
    """RPKI Trust Anchor Certificate Authority - RFC6487."""

    def __init__(self, *,
                 common_name: str = "TA",
                 base_uri: str = "rsync://rpki.example.net/rpki",
                 **kwargs: typing.Any) -> None:
        """Initialise the Certificate Authority."""
        log.info(f"doing initialisation of {self} as TACertificateAuthority")
        super().__init__(common_name=common_name, issuer=None, **kwargs)

    @property
    def repo_path(self) -> str:
        """Get the filesystem path to this CA's publication point."""
        return self.subject_cn

    @property
    def cert_path(self) -> str:
        """Get the filesystem path to cert in the publication point root."""
        return f"{self.subject_cn}.cer"

    @property
    def tal_path(self) -> str:
        """Get the filesystem path to the trust anchor locator."""
        return f"{self.subject_cn}.tal"

    @property
    def tal(self) -> bytes:
        """Get the contents of the TAL for this trust anchor."""
        tal_contents = f"{self.base_uri}/{self.cert_path}\n\n".encode()
        tal_contents += base64.b64encode(self.subject_public_key_info.to_der())
        return tal_contents

    def publish(self, *,
                pub_path: str,
                tal_path: typing.Optional[str] = None,
                recursive: bool = True,
                **kwargs: typing.Any) -> None:
        """Publish this CA's artifacts and TAL."""
        super().publish(pub_path=pub_path, recursive=recursive, **kwargs)
        if tal_path is not None:
            os.makedirs(tal_path, exist_ok=True)
            with open(os.path.join(tal_path, self.tal_path), "wb") as f:
                f.write(self.tal)
