import datetime
import os
import typing

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from .extensions import AsResources, IpResources
from .oid import RPKI_CERT_POLICY_OID
from ..cms import Certificate
from ..resources import AsResourcesInfo, IpResourcesInfo


class BaseResourceCertificate:

    # rfc6487 section 4.3
    HASH_ALGORITHM = hashes.SHA256()

    # rfc6487 section 4.8.9
    CPS = x509.CertificatePolicies([
        x509.PolicyInformation(RPKI_CERT_POLICY_OID,
                               policy_qualifiers=None)
    ])

    def __init__(self,
                 common_name: str = None,
                 days: int = 365,
                 issuer: "CertificateAuthority" = None,
                 ca: bool = False,
                 base_uri: str = "rsync://rpki.example.net/rpki",
                 ip_resources: IpResourcesInfo = None,
                 as_resources: AsResourcesInfo = None) -> None:

        self._issuer = issuer

        builder = x509.CertificateBuilder()

        # rfc6487 section 4.2
        serial_number = x509.random_serial_number()
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
            crldp = self.issuer.crldp(base_uri)
            builder = builder.add_extension(crldp, critical=False)
        # rfc6487 section 4.8.7
        if issuer is not None:
            aia = self.issuer.aia(base_uri)
            builder = builder.add_extension(aia, critical=False)
        # rfc6487 section 4.8.8
        sia = self.sia(base_uri)
        builder = builder.add_extension(sia, critical=False)
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
            self._cert = self.issue_cert()
        else:
            self._cert = self.issuer.issue_cert(self)

    @property
    def private_key(self):
        return self._key

    @property
    def public_key(self):
        return self._key.public_key()

    @property
    def cert_builder(self):
        return self._cert_builder

    @property
    def cert(self):
        return self._cert

    @property
    def cert_der(self):
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def issuer(self):
        return self._issuer

    @property
    def subject_cn(self):
        return self._cn

    @property
    def issuer_cn(self):
        if self.issuer is not None:
            return self.issuer.subject_cn
        else:
            return self.subject_cn

    @property
    def ski_digest(self):
        return self._ski_digest

    @property
    def mft_entry(self):
        return (os.path.basename(self.cert_path), self.cert_der)

    def asn1_data(self):
        c = Certificate.from_der(self.cert_der)
        return c.content_data

    @property
    def subject_public_key_info(self):
        c = Certificate.from_der(self.cert_der)
        return c.subject_public_key_info


ResourceCertificateList = typing.List[BaseResourceCertificate]
