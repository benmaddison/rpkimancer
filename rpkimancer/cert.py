import datetime
import os
import typing

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509

from .cms import Certificate
from .resources import (ASIdentifiers, AsResourcesInfo,
                        IPAddrBlocks, IpResourcesInfo)

AIA_CA_ISSUERS_OID = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
SIA_CA_REPOSITORY_OID = x509.oid.SubjectInformationAccessOID.CA_REPOSITORY
SIA_MFT_ACCESS_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.10")
SIA_OBJ_ACCESS_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.11")
RPKI_CERT_POLICY_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.14.2")
IP_RESOURCES_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.7")
AS_RESOURCES_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.8")

ResourceCertificateList = typing.List['ResourceCertificate']


class ResourceCertificate:

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
                 issuer: 'CertificateAuthority' = None,
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

    def asn1_data(self):
        c = Certificate.from_der(self.cert_der)
        return ("certificate", c.content_data)


class EECertificate(ResourceCertificate):
    def __init__(self, signed_object: "SignedObject", *args, **kwargs):
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


class CertificateAuthority(ResourceCertificate):
    def __init__(self,
                 common_name: str = None,
                 crl_days: int = 7,
                 *args, **kwargs) -> None:
        self._issued = list()
        super().__init__(common_name=common_name, ca=True, *args, **kwargs)
        # rfc 6487 section 5
        self._crl = None
        self.crl_days = crl_days
        self.next_crl_number = 0
        self.issue_crl()

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

    def crldp(self, base_uri):
        crldp_uri = f"{base_uri}/{self.crl_path}"
        crldp = x509.CRLDistributionPoints([
            x509.DistributionPoint([x509.UniformResourceIdentifier(crldp_uri)],
                                   relative_name=None,
                                   reasons=None,
                                   crl_issuer=None)
        ])
        return crldp

    def aia(self, base_uri):
        aia_uri = f"{base_uri}/{self.cert_path}"
        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(AIA_CA_ISSUERS_OID,
                                   x509.UniformResourceIdentifier(aia_uri))
        ])
        return aia

    def sia(self, base_uri, *args, **kwargs):
        sia_repo_uri = f"{base_uri}/{self.repo_path}"
        sia_mft_uri = f"{base_uri}/{self.mft_path}"
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(SIA_CA_REPOSITORY_OID,
                x509.UniformResourceIdentifier(sia_repo_uri)),  # noqa: E501
            x509.AccessDescription(SIA_MFT_ACCESS_OID,
                                   x509.UniformResourceIdentifier(sia_mft_uri))
        ])
        return sia

    def issue_cert(self, subject: ResourceCertificate = None):
        if subject is None:
            subject = self
        cert = subject.cert_builder.sign(private_key=self.private_key,
                                         algorithm=self.HASH_ALGORITHM)
        self._issued.append(subject)
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

    def publish(self, base_path, recursive=True):
        os.makedirs(os.path.join(base_path, self.repo_path), exist_ok=True)
        with open(os.path.join(base_path, self.cert_path), "wb") as f:
            f.write(self.cert_der)
        with open(os.path.join(base_path, self.crl_path), "wb") as f:
            f.write(self.crl_der)
        if recursive is True:
            for issuee in self.issued:
                if issuee is not self:
                    issuee.publish(base_path, recursive=recursive)


class TACertificateAuthority(CertificateAuthority):
    def __init__(self, common_name: str = "TA", *args, **kwargs) -> None:
        super().__init__(common_name=common_name, issuer=None, *args, **kwargs)

    @property
    def repo_path(self):
        return self.subject_cn

    @property
    def cert_path(self):
        return f"{self.subject_cn}.cer"


class IpResources(x509.UnrecognizedExtension):
    # TODO: IPAddressRange and inherit support
    def __init__(self, ip_resources: IpResourcesInfo):
        # def to_bitstring(network: ipaddress.ip_network):
        #     netbits = network.prefixlen
        #     hostbits = network.max_prefixlen - netbits
        #     value = int(network.network_address) >> hostbits
        #     return (value, netbits)
        # ip_address_blocks = [{"addressFamily": AFI[n.version],
        #                       "ipAddressChoice": ("addressesOrRanges",
        #                                           [("addressPrefix",
        #                                             to_bitstring(n))])}
        #                      for n in ip_resources]
        # IPAddrAndASCertExtn.IPAddrBlocks.set_val(ip_address_blocks)
        # ip_address_blocks_data = IPAddrAndASCertExtn.IPAddrBlocks.to_der()
        # IPAddrAndASCertExtn.IPAddrBlocks.reset_val()
        ip_address_blocks_data = IPAddrBlocks(ip_resources).to_der()
        super().__init__(IP_RESOURCES_OID, ip_address_blocks_data)


class AsResources(x509.UnrecognizedExtension):
    # TODO: inherit support
    def __init__(self, as_resources: AsResourcesInfo):
        # as_blocks = {"asnum": ("asIdsOrRanges",
        #                        [("id", a) for a in as_resources
        #                         if isinstance(a, int)] +
        #                        [("range", {"min": a[0], "max": a[1]})
        #                         for a in as_resources
        #                         if isinstance(a, tuple)])}
        # IPAddrAndASCertExtn.ASIdentifiers.set_val(as_blocks)
        # as_identifiers_data = IPAddrAndASCertExtn.ASIdentifiers.to_der()
        # IPAddrAndASCertExtn.ASIdentifiers.reset_val()
        as_identifiers_data = ASIdentifiers(as_resources).to_der()
        super().__init__(AS_RESOURCES_OID, as_identifiers_data)
