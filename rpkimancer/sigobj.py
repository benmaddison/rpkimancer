from .algorithms import SHA256
from .asn1 import PKIXAlgs_2009
from .cert import CertificateAuthority, EECertificate
from .cms import ContentInfo, SignedData
from .econtent import EncapsulatedContent

CMS_VERSION = 3


class SignedObject(ContentInfo):

    def __init__(self,
                 econtent: EncapsulatedContent,
                 issuer: CertificateAuthority):
        self._econtent = econtent
        # construct certificate
        ee_cert = EECertificate(signed_object=self,
                                issuer=issuer,
                                as_resources=[37271])
        # construct signedAttrs
        signed_attrs = econtent.signed_attrs()
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
                "eContentType": econtent.content_type.get_val(),
                # rfc6488 section 2.1.3.2
                "eContent": econtent.to_der(),
            },
            # rfc6488 section 2.1.4
            "certificates": [
                ee_cert.asn1_data()
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
                    # TODO: compute signature over 'signedAttrs'
                    "signature": signature
                    # 'unsignedAttrs' omitted per rfc6488 section 2.1.6.7
                }
            ]
        }
        super().__init__(content=SignedData(data))

    @property
    def econtent(self):
        return self._econtent
