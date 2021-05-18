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
"""X.509 ASN.1 Types - RFC5912."""

from __future__ import annotations

import logging

from ..asn1 import Content, append_info_object_set
from ..asn1.mod import PKIX1Explicit_2009
from ..asn1.types import ASN1Class

log = logging.getLogger(__name__)


class Certificate(Content):
    """X.509 ASN.1 Certificate type - RFC5912."""

    content_syntax = PKIX1Explicit_2009.Certificate

    @property
    def subject_public_key_info(self) -> SubjectPublicKeyInfo:
        """Get the subjectPublicKeyInfo of the Certificate."""
        log.info(f"trying to get subjectPublicKeyInfo data from {self}")
        with self.constructed() as instance:
            data = instance.get_val_at(["toBeSigned", "subjectPublicKeyInfo"])
        return SubjectPublicKeyInfo(data)

    @classmethod
    def register_ext_type(cls, ext_type: ASN1Class) -> None:
        """Add EXTENSION instance to extnID constraint set."""
        tbs_cert = cls.content_syntax.get_internals()["cont"]["toBeSigned"]
        extns = tbs_cert.get_internals()["cont"]["extensions"]
        extn_item = extns.get_internals()["cont"]
        extn_item_id = extn_item.get_internals()["cont"]["extnID"]
        extn_set = extn_item_id.get_const()["tab"]
        append_info_object_set(extn_set, ext_type)


class SubjectPublicKeyInfo(Content):
    """X.509 ASN.1 SubjectPublicKeyInfo type - RFC5912."""

    content_syntax = PKIX1Explicit_2009.SubjectPublicKeyInfo
