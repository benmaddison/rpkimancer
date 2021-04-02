import argparse
import ipaddress
import os


from .cert import CertificateAuthority, TACertificateAuthority
from .econtent import RpkiSignedURIList
from .sigobj import SignedObject

DEMO_ASN = 37271
DEMO_URI = "https://as37271.fyi/static/net_info_portal/md/bgp-communities.md"
COMMUNITY_DEFS_OID = (1, 3, 6, 1, 4, 1, 35743, 3)
DEMO_PUB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                             "target", "demo", "rpki")


def demo():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", nargs="+", default=[DEMO_URI],
                        dest="uri_list",
                        help="URIs to retrive and hash")
    parser.add_argument("--asn", default=DEMO_ASN,
                        help="ASN to include in resources")
    parser.add_argument("--content-type", default=COMMUNITY_DEFS_OID,
                        help="Content type of hashed data")
    args = parser.parse_args()
    # create CAs
    ta = TACertificateAuthority(ip_resources=[ipaddress.ip_network("0.0.0.0/0"),
                                              ipaddress.ip_network("::/0")],
                                as_resources=[(0, 4294967295)])
    ca1 = CertificateAuthority(common_name="CA1", issuer=ta,
                               ip_resources=[ipaddress.ip_network("41.78.188.0/22"),
                                             ipaddress.ip_network("197.157.64.0/19")],
                               as_resources=[37271])
    ca2 = CertificateAuthority(common_name="CA2", issuer=ca1,
                               as_resources=[37271])
    # create RSU
    econtent = RpkiSignedURIList(*args.uri_list,
                                 inner_type=args.content_type,
                                 as_resources=[args.asn])
    rsu = SignedObject(econtent=econtent,
                       issuer=ca2)
    # publish objects
    ta.publish(base_path=DEMO_PUB_PATH)


if __name__ == "__main__":
    demo()
