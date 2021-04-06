from ..algorithms import DIGEST_ALGORITHMS, SHA256
from ..asn1 import PKIXAlgs_2009
from ..cms import Content, ContentInfo, SignedAttributes, SignedData

CMS_VERSION = 3


class EncapsulatedContent(Content):

    digest_algorithm = DIGEST_ALGORITHMS[SHA256]

    def digest(self):
        return self.digest_algorithm(self.to_der()).digest()

    def signed_attrs(self):
        return SignedAttributes(content_type=self.content_type.get_val(),
                                message_digest=self.digest())

    def signed_attrs_digest(self):
        return self.digest_algorithm(self.signed_attrs().to_der()).hexdigest()


class SignedObject(ContentInfo):

    econtent_cls = None

    def __init__(self, issuer: "CertificateAuthority", *args, **kwargs):
        # construct econtent
        self._econtent = self.econtent_cls(*args, **kwargs)
        # construct certificate
        from ..cert import EECertificate
        ee_cert = EECertificate(signed_object=self,
                                issuer=issuer,
                                as_resources=[37271])
        # construct signedAttrs
        signed_attrs = self.econtent.signed_attrs()
        # construct signature
        signature = ee_cert.sign_object()

        data = {
            # rfc6488 section 2.1.1
            "version": CMS_VERSION,
            # rfc6488 section 2.1.2 and rfc7935
            "digestAlgorithms": [{"algorithm": SHA256}],
            # rfc6488 section 2.1.3
            "encapContentInfo": {
                # rfc6488 section 2.1.3.1
                "eContentType": self.econtent.content_type.get_val(),
                # rfc6488 section 2.1.3.2
                "eContent": self.econtent.to_der(),
            },
            # rfc6488 section 2.1.4
            "certificates": [
                ("certificate", ee_cert.asn1_data())
            ],
            # 'crls' omitted per rfc6488 section 2.1.5
            # rfc6488 section 2.1.6
            "signerInfos": [
                {
                    # rfc6488 section 2.1.6.1
                    "version": CMS_VERSION,
                    # rfc6488 section 2.1.6.2
                    "sid": ("subjectKeyIdentifier", ee_cert.ski_digest),
                    # rfc6488 section 2.1.6.3
                    "digestAlgorithm": {"algorithm": SHA256},
                    # rfc6488 section 2.1.6.4
                    "signedAttrs": signed_attrs.content_data,
                    # rfc6488 section 2.1.6.5 and rfc7935
                    "signatureAlgorithm": {
                        "algorithm": PKIXAlgs_2009.rsaEncryption.get_val()
                    },
                    # rfc6488 section 2.1.6.6
                    "signature": signature
                    # 'unsignedAttrs' omitted per rfc6488 section 2.1.6.7
                }
            ]
        }
        super().__init__(content=SignedData(data))

    @property
    def econtent(self):
        return self._econtent
