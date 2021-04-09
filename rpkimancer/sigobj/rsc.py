import os
import typing
import urllib.request

from .base import EncapsulatedContent, SignedObject
from ..algorithms import DIGEST_ALGORITHMS, SHA256
from ..asn1 import RpkiSignedChecklist_2021
from ..resources import (IPList, IpResourcesInfo,
                         ASIdOrRange, AsResourcesInfo)


class RpkiSignedChecklistEContent(EncapsulatedContent):

    content_type = RpkiSignedChecklist_2021.id_ct_signedChecklist
    content_syntax = RpkiSignedChecklist_2021.RpkiSignedChecklist
    file_ext = "sig"

    def __init__(self,
                 paths: typing.List[str] = [],
                 version: int = 0,
                 ip_resources: IpResourcesInfo = None,
                 as_resources: AsResourcesInfo = None,
                 digest_algorithm=SHA256):
        checklist = list()
        alg = DIGEST_ALGORITHMS[digest_algorithm]
        for path in paths:
            with open(path, "rb") as f:
                data = f.read()
            digest = alg(data).digest()
            checklist.append({"filename": os.path.basename(path),
                              "hash": digest})
        data = {"version": version,
                "digestAlgorithm": {"algorithm": digest_algorithm},
                "checkList": checklist,
                "resources": {}}
        if ip_resources is not None:
            data["resources"]["ipAddrBlocks"] = IPList(ip_resources)
        if as_resources is not None:
            data["resources"]["asID"] = [ASIdOrRange(a).content_data
                                         for a in as_resources]
        super().__init__(data)
        self.as_resources = as_resources
        self.ip_resources = ip_resources


class RpkiSignedChecklist(SignedObject):

    econtent_cls = RpkiSignedChecklistEContent
