import argparse

from . import RpkiSignedURIList

def demo():
    default_asn = 37271
    default_uri = "https://as37271.fyi/static/net_info_portal/md/bgp-communities.md"
    community_definitions_content = (1, 3, 6, 1, 4, 1, 35743, 3)
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", nargs="+", default=[default_uri],
                        dest="uri_list",
                        help="URIs to retrive and hash")
    parser.add_argument("--asn", default=default_asn,
                        help="ASN to include in resources")
    parser.add_argument("--content-type", default=community_definitions_content,
                        help="Content type of hashed data")
    args = parser.parse_args()
    rsu = RpkiSignedURIList(*args.uri_list,
                            version=0,
                            resources=dict(asID=[("id", args.asn)]),
                            type=args.content_type)
    print(rsu.to_asn1())


if __name__ == "__main__":
    demo()
