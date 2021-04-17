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
"""Base RPKI Resource Certificate implementation - RFC6487."""

from __future__ import annotations

import datetime
import logging
import os
import typing
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .extensions import AsResources, IpResources
from .oid import RPKI_CERT_POLICY_OID
from ..asn1 import Content, PKIX1Explicit_2009
from ..resources import AsResourcesInfo, IpResourcesInfo

if typing.TYPE_CHECKING:
    from .ca import CertificateAuthority

log = logging.getLogger(__name__)

ManifestEntryInfo = typing.Tuple[str, bytes]


class BaseResourceCertificate:
    """Base RPKI Resource Certificate class - RFC6487."""

    # rfc6487 section 4.3
    HASH_ALGORITHM = hashes.SHA256()

    # rfc6487 section 4.8.9
    CPS = x509.CertificatePolicies([
        x509.PolicyInformation(RPKI_CERT_POLICY_OID,
                               policy_qualifiers=None),
    ])

    def __init__(self, *,  # noqa: R701
                 common_name: str,
                 days: int = 365,
                 issuer: typing.Optional[CertificateAuthority] = None,
                 ca: bool = False,
                 base_uri: str = "rsync://rpki.example.net/rpki",
                 ip_resources: typing.Optional[IpResourcesInfo] = None,
                 as_resources: typing.Optional[AsResourcesInfo] = None) -> None:  # noqa: E501
        """Initialise the Resource Certificate."""
        self._issuer = issuer
        self._base_uri = urllib.parse.urlparse(base_uri)

        builder = x509.CertificateBuilder()

        # rfc6487 section 4.2
        if self.issuer is None:
            serial_number = typing.cast("CertificateAuthority",
                                        self).next_serial_number
        else:
            serial_number = self.issuer.next_serial_number
        builder = builder.serial_number(serial_number)
        # rfc6487 section 4.5
        self._cn = common_name
        subject_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                                     self.subject_cn)])
        builder = builder.subject_name(subject_name)
        # rfc6487 section 4.4
        if self.issuer is None:
            issuer_name = subject_name
        else:
            issuer_name = self.issuer.cert.subject
        builder = builder.issuer_name(issuer_name)
        # rfc6487 section 4.6
        valid_from = datetime.datetime.utcnow()
        valid_to = valid_from + datetime.timedelta(days=days)
        builder = builder.not_valid_before(valid_from) \
                         .not_valid_after(valid_to)
        # rfc6487 sect 4.7 and rfc7935 section 3
        self._key = rsa.generate_private_key(public_exponent=65537,
                                             key_size=2048)
        builder = builder.public_key(self.public_key)
        # rfc6487 section 4.8.1
        if ca is True:
            basic_constraints = x509.BasicConstraints(ca=True,
                                                      path_length=None)
            builder = builder.add_extension(basic_constraints, critical=True)
        # rfc6487 section 4.8.2
        ski = x509.SubjectKeyIdentifier.from_public_key(self.public_key)
        self._ski_digest = ski.digest
        builder = builder.add_extension(ski, critical=False)
        # rfc6487 section 4.8.3
        if self.issuer is not None:
            aki = x509.AuthorityKeyIdentifier\
                      .from_issuer_public_key(self.issuer.public_key)
            builder = builder.add_extension(aki, critical=False)
        # rfc6487 section 4.8.4
        key_usage = x509.KeyUsage(digital_signature=ca is False,
                                  key_cert_sign=ca is True,
                                  crl_sign=ca is True,
                                  content_commitment=False,
                                  key_encipherment=False,
                                  data_encipherment=False,
                                  key_agreement=False,
                                  encipher_only=False,
                                  decipher_only=False)
        builder = builder.add_extension(key_usage, critical=True)
        # rfc6487 section 4.8.6
        if self.issuer is not None:
            builder = builder.add_extension(self.issuer.crldp, critical=False)
        # rfc6487 section 4.8.7
        if self.issuer is not None:
            builder = builder.add_extension(self.issuer.aia, critical=False)
        # rfc6487 section 4.8.8
        builder = builder.add_extension(self.sia, critical=False)
        # rfc6487 section 4.8.9
        builder = builder.add_extension(self.CPS, critical=True)
        # rfc6487 section 4.8.10
        if ip_resources is not None:
            ip_resources_ext = IpResources(ip_resources)
            builder = builder.add_extension(ip_resources_ext, critical=True)
        # rfc6487 section 4.8.11
        if as_resources is not None:
            as_resources_ext = AsResources(as_resources)
            builder = builder.add_extension(as_resources_ext, critical=True)

        self._cert_builder = builder

        if self.issuer is None:
            self._cert = typing.cast("CertificateAuthority", self).issue_cert()
        else:
            self._cert = self.issuer.issue_cert(self)

    @property
    def sia(self) -> x509.SubjectInformationAccess:
        """Construct the SIA extension."""
        raise NotImplementedError

    @property
    def mft_entry(self) -> ManifestEntryInfo:
        """Get an entry for inclusion in the issuer's manifest."""
        raise NotImplementedError

    def publish(self, *, pub_path: str, recursive: bool = True) -> None:
        """Publish artifact files in the PP."""
        raise NotImplementedError

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        """Get the private part of the RSA key pair."""
        return self._key

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        """Get the public part of the RSA key pair."""
        return self._key.public_key()

    @property
    def cert_builder(self) -> x509.CertificateBuilder:
        """Get the certificate builder used to construct the certificate."""
        return self._cert_builder

    @property
    def base_uri(self) -> str:
        """Get the base URI of the RPKI publication service."""
        return self._base_uri.geturl()

    @property
    def uri_path(self) -> str:
        """Get the relative filesystem path equivalent of base_uri."""
        return os.path.join(self._base_uri.hostname or "",
                            *self._base_uri.path.rstrip("/").split("/"))

    @property
    def cert(self) -> x509.Certificate:
        """Get the underlying cryptography X.509 Certificate object."""
        return self._cert

    @property
    def cert_der(self) -> bytes:
        """Get cert DER-encoded."""
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def issuer(self) -> typing.Optional[CertificateAuthority]:
        """Get the issuing CertificateAuthority."""
        return self._issuer

    @property
    def subject_cn(self) -> str:
        """Get the common_name component of the subjectName."""
        return self._cn

    @property
    def issuer_cn(self) -> str:
        """Get the common_name component of the issuerName."""
        if self.issuer is not None:
            return self.issuer.subject_cn
        else:
            return self.subject_cn

    @property
    def ski_digest(self) -> bytes:
        """Get the message digest of the SKI extension."""
        return self._ski_digest

    @property
    def asn1_cert(self) -> Certificate:
        """Get an ASN.1 Certificate for the certificate."""
        return Certificate.from_der(self.cert_der)

    @property
    def subject_public_key_info(self) -> SubjectPublicKeyInfo:
        """Get the subjectPublicKeyInfo for the certificate."""
        return self.asn1_cert.subject_public_key_info


ResourceCertificates = typing.Iterable[BaseResourceCertificate]
ResourceCertificateList = typing.List[BaseResourceCertificate]


class Certificate(Content):
    """X.509 ASN.1 Certificate type - RFC5912."""

    content_syntax = PKIX1Explicit_2009.Certificate

    @property
    def subject_public_key_info(self) -> SubjectPublicKeyInfo:
        """Get the subjectPublicKeyInfo of the Certificate."""
        with self.constructed() as instance:
            data = instance.get_val_at(["toBeSigned", "subjectPublicKeyInfo"])
        return SubjectPublicKeyInfo(data)


class SubjectPublicKeyInfo(Content):
    """X.509 ASN.1 SubjectPublicKeyInfo type - RFC5912."""

    content_syntax = PKIX1Explicit_2009.SubjectPublicKeyInfo
