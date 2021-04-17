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
"""Classes implementing CMS ASN.1 types."""

from __future__ import annotations

import logging

from .asn1 import Content
from .asn1.mod import CryptographicMessageSyntax_2009
from .asn1.types import OID

log = logging.getLogger(__name__)


class ContentData(Content):
    """Generic base class for ASN.1 types idenitied by an OID."""

    content_type: OID


class ContentInfo(Content):
    """CMS ASN.1 ContentInfo type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.ContentInfo

    def __init__(self, content: ContentData) -> None:
        """Initialise the instance from contained ContentData."""
        content_type_oid = content.content_type.get_val()
        content_type_name = content.content_syntax.fullname()
        content_data = content.content_data
        data = {"contentType": content_type_oid,
                "content": (content_type_name, content_data)}
        super().__init__(data)


class SignedData(ContentData):
    """CMS ASN.1 SignedData type - RFC5911."""

    content_type = CryptographicMessageSyntax_2009.id_signedData
    content_syntax = CryptographicMessageSyntax_2009.SignedData


class SignedAttributes(Content):
    """CMS ASN.1 SignedAttributes type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.SignedAttributes

    def __init__(self, content_type: OID, message_digest: bytes) -> None:
        """Initialise the instance from an eContentType and eContent digest."""
        ct_attr_oid = CryptographicMessageSyntax_2009.id_contentType.get_val()
        md_attr_oid = CryptographicMessageSyntax_2009.id_messageDigest.get_val()  # noqa: E501
        data = [
            {
                "attrType": ct_attr_oid,
                "attrValues": [('ContentType', content_type.get_val())],
            },
            {
                "attrType": md_attr_oid,
                "attrValues": [('MessageDigest', message_digest)],
            },
        ]
        super().__init__(data)
