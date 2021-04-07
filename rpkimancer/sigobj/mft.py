import datetime
import typing

from .base import EncapsulatedContent, SignedObject
from ..algorithms import SHA256
from ..asn1 import RPKIManifest
from ..resources import INHERIT_AS, INHERIT_IPV4, INHERIT_IPV6


class RpkiManifestEContent(EncapsulatedContent):

    content_type = RPKIManifest.id_ct_rpkiManifest
    content_syntax = RPKIManifest.Manifest
    file_ext = "mft"
    as_resources = INHERIT_AS
    ip_resources = [INHERIT_IPV4, INHERIT_IPV6]

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
                              "hash": self.hash_bitstring(f[1])}
                             for f in file_list]}
        super().__init__(data)

    @staticmethod
    def generalized_time(timestamp: datetime.datetime):
        return tuple(f"{t:02}" for t in timestamp.timetuple()[:4]) + \
               tuple(None for _ in range(4))

    def hash_bitstring(self, contents: bytes):
        digest = self.digest_algorithm(contents).digest()
        hash_bits = int.from_bytes(digest, "big")
        hash_len = len(digest) * 8
        return (hash_bits, hash_len)


class RpkiManifest(SignedObject):

    econtent_cls = RpkiManifestEContent
