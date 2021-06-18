# Copyright (c) 2021 Ben Maddison. All rights reserved.
#
# The contents of this file are licensed under the MIT License
# (the "License"); you may not use this file except in compliance with the
# License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""RPKI Manifest implementation - RFC6486."""

from __future__ import annotations

import datetime
import logging
import typing

from .base import EncapsulatedContentType, SignedObject
from ..algorithms import SHA256
from ..asn1.mod import RPKIManifest
from ..resources import INHERIT_AS, INHERIT_IPV4, INHERIT_IPV6

log = logging.getLogger(__name__)

GeneralizedTimeInfo = typing.Tuple[typing.Optional[str], ...]
HashInfo = typing.Tuple[int, int]
FileListInfo = typing.List[typing.Tuple[str, bytes]]


class RpkiManifestContentType(EncapsulatedContentType):
    """encapContentInfo for RPKI Manifests - RFC6486."""

    asn1_definition = RPKIManifest.ct_rpkiManifest
    file_ext = "mft"
    as_resources = INHERIT_AS
    ip_resources: typing.Final = (INHERIT_IPV4, INHERIT_IPV6)

    def __init__(self, *,
                 version: int = 0,
                 manifest_number: int = 0,
                 this_update: datetime.datetime,
                 next_update: datetime.datetime,
                 file_list: FileListInfo) -> None:
        """Initialise the encapContentInfo."""
        log.info(f"preparing data for {self}")
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
    def generalized_time(timestamp: datetime.datetime) -> GeneralizedTimeInfo:
        """Construct ASN.1 GeneralizedTime data from python datetime."""
        return tuple(f"{t:02}" for t in timestamp.timetuple()[:4]) + \
               tuple(None for _ in range(4))  # noqa: E127

    def hash_bitstring(self, contents: bytes) -> HashInfo:
        """Construct ASN.1 BIT STRING of a hash over file contents."""
        digest = self.digest_algorithm(contents).digest()  # type: ignore[call-arg, arg-type, misc] # noqa: E501
        hash_bits = int.from_bytes(digest, "big")
        hash_len = len(digest) * 8
        return (hash_bits, hash_len)


class RpkiManifest(SignedObject[RpkiManifestContentType]):
    """CMS ASN.1 ContentInfo for RPKI Manifests."""
