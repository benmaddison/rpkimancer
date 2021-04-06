from cryptography import x509


AIA_CA_ISSUERS_OID = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
SIA_CA_REPOSITORY_OID = x509.oid.SubjectInformationAccessOID.CA_REPOSITORY
SIA_MFT_ACCESS_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.10")
SIA_OBJ_ACCESS_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.11")
RPKI_CERT_POLICY_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.14.2")
IP_RESOURCES_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.7")
AS_RESOURCES_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.8")
