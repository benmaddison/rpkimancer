import datetime
import ipaddress
import typing

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from .rpki_rsu import IPAddrAndASCertExtn


def make_cert(common_name: str = "TA",
              days: int = 365,
              issuer: x509.Certificate = None,
              ca: bool = True,
              signed_object_type: str = None,
              ip_resources: typing.List[ipaddress.ip_network] = None,
              as_resources: typing.List[typing.Union[int, typing.Tuple[int, int]]] = None) -> x509.Certificate:
    publication_point_base_uri = "rsync://localhost/rpki"

    builder = x509.CertificateBuilder()

    # rfc6487 section 4.2
    serial_number = x509.random_serial_number()
    builder = builder.serial_number(serial_number)
    # rfc6487 section 4.3
    hash_algorithm = hashes.SHA256()
    # rfc6487 section 4.5
    subject_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    builder = builder.subject_name(subject_name)
    # rfc6487 section 4.4
    if issuer is None:
        issuer_name = subject_name
    else:
        issuer_name = issuer.subject
    builder = builder.issuer_name(issuer_name)
    # rfc6487 section 4.6
    valid_from = datetime.datetime.utcnow()
    valid_to = valid_from + datetime.timedelta(days=days)
    builder = builder.not_valid_before(valid_from) \
                     .not_valid_after(valid_to)
    # rfc6487 sect 4.7 and rfc7935 section 3
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = builder.public_key(key.public_key())
    # rfc6487 section 4.8.1
    if ca is True:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                        critical=True)
    # rfc6487 section 4.8.2
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                                    critical=False)
    # rfc6487 section 4.8.3
    if issuer is not None:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()),
                                        critical=False)
    # rfc6487 section 4.8.4
    builder = builder.add_extension(x509.KeyUsage(digital_signature=ca is False,
                                                  key_cert_sign=ca is True,
                                                  crl_sign=ca is True,
                                                  content_commitment=False,
                                                  key_encipherment=False,
                                                  data_encipherment=False,
                                                  key_agreement=False,
                                                  encipher_only=False,
                                                  decipher_only=False),
                                    critical=True)
    # rfc6487 section 4.8.6
    if issuer is not None:
        crldp_uri = f"{publication_point_base_uri}/{issuer.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}/revoked.crl"
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint([x509.UniformResourceIdentifier(crldp_uri)],
                                   relative_name=None, reasons=None, crl_issuer=None)
        ]), critical=False)
    # rfc6487 section 4.8.7
    if issuer is not None:
        if issuer.issuer == issuer.subject:
            aia_uri = f"{publication_point_base_uri}/{issuer.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}.cer"
        else:
            aia_uri = f"{publication_point_base_uri}/{issuer.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}/{issuer.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}.cer"
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier(aia_uri))
            ]), critical=False)
    # rfc6487 section 4.8.8
    if ca is True:
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(x509.oid.SubjectInformationAccessOID.CA_REPOSITORY,
                                   x509.UniformResourceIdentifier(f"{publication_point_base_uri}/{common_name}")),
            x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.10"),
                                   x509.UniformResourceIdentifier(f"{publication_point_base_uri}/{common_name}/manifest.mft"))
        ])
    else:
        sia = x509.SubjectInformationAccess([
            x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.11"),
                                   x509.UniformResourceIdentifier(f"{publication_point_base_uri}/{issuer.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}/{common_name}.{signed_object_type}"))
        ])
    builder = builder.add_extension(sia, critical=False)
    # rfc6487 section 4.8.9
    builder = builder.add_extension(x509.CertificatePolicies([
        x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.5.5.7.14.2"),
                               policy_qualifiers=None)
    ]), critical=True)
    # rfc6487 section 4.8.10 (TODO: IPAddressRange and inherit support)
    if ip_resources is not None:
        afi = {4: (1).to_bytes(2, "big"),
               6: (2).to_bytes(2, "big")}
        ip_address_blocks = [{"addressFamily": afi[n.version],
                              "ipAddressChoice": ("addressesOrRanges",
                                                  [("addressPrefix",
                                                   (int(n.network_address),
                                                    n.prefixlen))])}
                             for n in ip_resources]
        IPAddrAndASCertExtn.IPAddrBlocks.set_val(ip_address_blocks)
        ip_address_blocks_data = IPAddrAndASCertExtn.IPAddrBlocks.to_der()
        IPAddrAndASCertExtn.IPAddrBlocks.reset_val()
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.7"),
                                                         ip_address_blocks_data),
                              critical=True)
    # rfc6487 section 4.8.11 (TODO: ASRange and inherit support)
    if as_resources is not None:
        as_blocks = {"asnum": ("asIdsOrRanges",
                               [("id", a) for a in as_resources if isinstance(a, int)] +
                               [("range", {"min": a[0], "max": a[1]}) for a in as_resources
                                if isinstance(a, tuple)])}
        IPAddrAndASCertExtn.ASIdentifiers.set_val(as_blocks)
        as_identifiers_data = IPAddrAndASCertExtn.ASIdentifiers.to_der()
        IPAddrAndASCertExtn.ASIdentifiers.reset_val()
        builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.8"),
                                                                   as_identifiers_data),
                                        critical=True)

    cert = builder.sign(private_key=key, algorithm=hash_algorithm)
    return cert
