import datetime
import ipaddress
import typing

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from .asn1 import IPAddrAndASCertExtn

AIA_CA_ISSUERS_OID = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
SIA_CA_REPOSITORY_OID = x509.oid.SubjectInformationAccessOID.CA_REPOSITORY
SIA_MFT_ACCESS_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.10")
SIA_OBJ_ACCESS_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.11")
RPKI_CERT_POLICY_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.14.2")
IP_RESOURCES_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.7")
AS_RESOURCES_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.8")

AFI = {4: (1).to_bytes(2, "big"),
       6: (2).to_bytes(2, "big")}

IpResourcesInfo = typing.List[ipaddress.ip_network]
AsResourcesInfo = typing.List[typing.Union[int,
                                           typing.Tuple[int, int]]]


class ResourceCertificate:
    def __init__(self,
                 common_name: str = "TA",
                 days: int = 365,
                 issuer: 'ResourceCertificate' = None,
                 ca: bool = True,
                 signed_object_type: str = None,
                 base_uri: str = "rsync://rpki.example.net/rpki",
                 ip_resources: IpResourcesInfo = None,
                 as_resources: AsResourcesInfo = None) -> None:

        builder = x509.CertificateBuilder()

        # rfc6487 section 4.2
        serial_number = x509.random_serial_number()
        builder = builder.serial_number(serial_number)
        # rfc6487 section 4.3
        hash_algorithm = hashes.SHA256()
        # rfc6487 section 4.5
        subject_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                                     common_name)])
        builder = builder.subject_name(subject_name)
        # rfc6487 section 4.4
        if issuer is None:
            issuer_name = subject_name
        else:
            issuer_name = issuer.cert.subject
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
        builder = builder.add_extension(ski, critical=False)
        # rfc6487 section 4.8.3
        if issuer is not None:
            aki = x509.AuthorityKeyIdentifier\
                      .from_issuer_public_key(issuer.public_key)
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
        if issuer is not None:
            crldp_uri = f"{base_uri}/{issuer.subject_cn}/revoked.crl"
            crldp = x509.CRLDistributionPoints([
                x509.DistributionPoint([x509.UniformResourceIdentifier(crldp_uri)],
                                       relative_name=None,
                                       reasons=None,
                                       crl_issuer=None)
            ])
            builder = builder.add_extension(crldp, critical=False)
        # rfc6487 section 4.8.7
        if issuer is not None:
            if issuer.cert.issuer == issuer.cert.subject:
                aia_uri = f"{base_uri}/{issuer.subject_cn}.cer"
            else:
                aia_uri = f"{base_uri}/{issuer.issuer_cn}/{issuer.subject_cn}.cer"
            aia = x509.AuthorityInformationAccess([
                x509.AccessDescription(AIA_CA_ISSUERS_OID,
                                       x509.UniformResourceIdentifier(aia_uri))
            ])
            builder = builder.add_extension(aia, critical=False)
        # rfc6487 section 4.8.8
        if ca is True:
            sia_repo_uri = f"{base_uri}/{common_name}"
            sia_mft_uri = f"{base_uri}/{common_name}/manifest.mft"
            sia = x509.SubjectInformationAccess([
                x509.AccessDescription(SIA_CA_REPOSITORY_OID,
                                       x509.UniformResourceIdentifier(sia_repo_uri)),
                x509.AccessDescription(SIA_MFT_ACCESS_OID,
                                       x509.UniformResourceIdentifier(sia_mft_uri))
            ])
        else:
            sia_obj_uri = f"{base_uri}/{issuer.subject_cn}/{common_name}.{signed_object_type}"
            sia = x509.SubjectInformationAccess([
                x509.AccessDescription(SIA_OBJ_ACCESS_OID,
                                       x509.UniformResourceIdentifier(sia_obj_uri))
            ])
        builder = builder.add_extension(sia, critical=False)
        # rfc6487 section 4.8.9
        cps = x509.CertificatePolicies([
            x509.PolicyInformation(RPKI_CERT_POLICY_OID,
                                   policy_qualifiers=None)
        ])
        builder = builder.add_extension(cps, critical=True)
        # rfc6487 section 4.8.10 (TODO: IPAddressRange and inherit support)
        if ip_resources is not None:
            ip_resources_ext = IpResources(ip_resources)
            builder = builder.add_extension(ip_resources_ext, critical=True)
        # rfc6487 section 4.8.11 (TODO: ASRange and inherit support)
        if as_resources is not None:
            as_resources_ext = AsResources(as_resources)
            builder = builder.add_extension(as_resources_ext, critical=True)

        if issuer is None:
            signing_key = self.private_key
        else:
            signing_key = issuer.private_key
        self._cert = builder.sign(private_key=signing_key,
                                  algorithm=hash_algorithm)

    @property
    def private_key(self):
        return self._key

    @property
    def public_key(self):
        return self._key.public_key()

    @property
    def cert(self):
        return self._cert

    @property
    def subject_cn(self):
        cn = x509.NameOID.COMMON_NAME
        return self._cert.subject.get_attributes_for_oid(cn)[0].value

    @property
    def issuer_cn(self):
        cn = x509.NameOID.COMMON_NAME
        return self._cert.issuer.get_attributes_for_oid(cn)[0].value


class IpResources(x509.UnrecognizedExtension):
    def __init__(self, ip_resources: IpResourcesInfo):
        ip_address_blocks = [{"addressFamily": AFI[n.version],
                              "ipAddressChoice": ("addressesOrRanges",
                                                  [("addressPrefix",
                                                   (int(n.network_address),
                                                    n.prefixlen))])}
                             for n in ip_resources]
        IPAddrAndASCertExtn.IPAddrBlocks.set_val(ip_address_blocks)
        ip_address_blocks_data = IPAddrAndASCertExtn.IPAddrBlocks.to_der()
        IPAddrAndASCertExtn.IPAddrBlocks.reset_val()
        super().__init__(IP_RESOURCES_OID, ip_address_blocks_data)


class AsResources(x509.UnrecognizedExtension):
    def __init__(self, as_resources: AsResourcesInfo):
        as_blocks = {"asnum": ("asIdsOrRanges",
                               [("id", a) for a in as_resources
                                if isinstance(a, int)] +
                               [("range", {"min": a[0], "max": a[1]})
                                for a in as_resources
                                if isinstance(a, tuple)])}
        IPAddrAndASCertExtn.ASIdentifiers.set_val(as_blocks)
        as_identifiers_data = IPAddrAndASCertExtn.ASIdentifiers.to_der()
        IPAddrAndASCertExtn.ASIdentifiers.reset_val()
        super().__init__(AS_RESOURCES_OID, as_identifiers_data)
