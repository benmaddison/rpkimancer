import typing
import urllib.request

from .base import EncapsulatedContent, SignedObject
from ..algorithms import DIGEST_ALGORITHMS, SHA256
from ..asn1 import RpkiSignedURIList_2021
from ..resources import (IPAddressFamily, IpResourcesInfo,
                         ASIdOrRange, AsResourcesInfo)


class RpkiSignedURIListEContent(EncapsulatedContent):

    content_type = RpkiSignedURIList_2021.id_ct_signedURIList
    content_syntax = RpkiSignedURIList_2021.RpkiSignedURIList
    file_ext = "rsu"

    def __init__(self,
                 uris: typing.List[str] = [],
                 version: int = 0,
                 inner_type: typing.Tuple[int] = None,
                 ip_resources: IpResourcesInfo = None,
                 as_resources: AsResourcesInfo = None,
                 digest_algorithm=SHA256):
        uri_list = list()
        alg = DIGEST_ALGORITHMS[digest_algorithm]
        for uri in uris:
            hasher = alg()
            with urllib.request.urlopen(uri) as response:
                data = response.read()
            length = len(data)
            hasher.update(data)
            digest = hasher.digest()
            uri_list.append(dict(uri=uri, size=length, hash=digest))
        data = {"version": version,
                "digestAlgorithm": {"algorithm": digest_algorithm},
                "uriList": uri_list,
                "resources": {}}
        if inner_type is not None:
            data["type"] = inner_type
        if ip_resources is not None:
            data["resources"]["ipAddrBlocks"] = [IPAddressFamily(n).content_data  # noqa: E501
                                                 for n in ip_resources]
        if as_resources is not None:
            data["resources"]["asID"] = [ASIdOrRange(a).content_data
                                         for a in as_resources]
        super().__init__(data)


class RpkiSignedURIList(SignedObject):

    econtent_cls = RpkiSignedURIListEContent
