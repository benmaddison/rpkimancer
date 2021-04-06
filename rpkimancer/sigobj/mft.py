import datetime
import typing

from .base import EncapsulatedContent, SignedObject
from ..algorithms import SHA256
from ..asn1 import RPKIManifest


class RpkiManifestEContent(EncapsulatedContent):

    content_type = RPKIManifest.id_ct_rpkiManifest
    content_syntax = RPKIManifest.Manifest
    file_ext = "mft"

    _file_list_type = typing.List[typing.Tuple[str, bytes]]

    def __init__(self,
                 version: int = 0,
                 manifest_number: int = 0,
                 this_update: datetime.datetime = None,
                 next_update: datetime.datetime = None,
                 file_list: _file_list_type = []):
        data = {"version": version,
                "manifestNumber": manifest_number,
                "thisUpdate": self.generalized_time(this_update),
                "nextUpdate": self.generalized_time(next_update),
                "fileHashAlg": SHA256,
                "fileList": [{"file": f[0],
                              "hash": (int.from_bytes(self.digest_algorithm(f[1]).digest(), "big"), 256)}
                             for f in file_list]}
        super().__init__(data)

    @staticmethod
    def generalized_time(timestamp: datetime.datetime):
        return tuple(f"{t:02}" for t in timestamp.timetuple()[:4]) + \
               tuple(None for _ in range(4))


class RpkiManifest(SignedObject):

    econtent_cls = RpkiManifestEContent
