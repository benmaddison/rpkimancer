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
import typing

from .asn1 import Content, append_info_object_set
from .asn1.mod import CryptographicMessageSyntax_2009
from .asn1.types import ASN1Class, OID

log = logging.getLogger(__name__)

ContentDataSubclass = typing.TypeVar("ContentDataSubclass",
                                     bound="ContentData")


class ContentData(Content):
    """Generic base class for ASN.1 types idenitied by an OID."""

    content_type: OID


class ContentInfo(Content):
    """CMS ASN.1 ContentInfo type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.ContentInfo

    def __init__(self, content: ContentData) -> None:
        """Initialise the instance from contained ContentData."""
        log.info(f"preparing data for {self}")
        content_type_oid = content.content_type.get_val()
        content_type_name = content.content_syntax.fullname()
        content_data = content.content_data
        data = {"contentType": content_type_oid,
                "content": (content_type_name, content_data)}
        super().__init__(data)

    @classmethod
    def register_econtent_type(cls,
                               content_type: typing.Type[ContentDataSubclass],
                               econtent_type: ASN1Class) -> None:
        """Add CONTENT-TYPE instance to eContentType constraint set."""
        content = cls.content_syntax.get_internals()["cont"]["content"]
        content_const_set = content.get_const()["tab"].get_val()
        content_type_oid = content_type.content_type.get_val()
        content_data_inst = list(filter(lambda item: item["id"] == content_type_oid,  # noqa: E501
                                        content_const_set.getv()))[0]["Type"]
        encap_content_info = content_data_inst.get_internals()["cont"]["encapContentInfo"]  # noqa: E501
        econtent_open_type = encap_content_info.get_internals()["cont"]["eContentType"]  # noqa: E501
        econtent_const_set = econtent_open_type.get_const()["tab"]
        append_info_object_set(econtent_const_set, econtent_type)


class SignedData(ContentData):
    """CMS ASN.1 SignedData type - RFC5911."""

    content_type = CryptographicMessageSyntax_2009.id_signedData
    content_syntax = CryptographicMessageSyntax_2009.SignedData


class SignedAttributes(Content):
    """CMS ASN.1 SignedAttributes type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.SignedAttributes

    def __init__(self, content_type: OID, message_digest: bytes) -> None:
        """Initialise the instance from an eContentType and eContent digest."""
        log.info(f"preparing data for {self}")
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


class EncapsulatedContentInfo(Content):
    """CMS ASN.1 EncapsulatedContentInfo type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.EncapsulatedContentInfo

    @classmethod
    def from_content_info(cls,
                          content_info: ContentInfo) -> EncapsulatedContentInfo:  # noqa: E501
        """De-encapsulate from ContentInfo instance."""
        val_path = ["content", "SignedData", "encapContentInfo"]
        with content_info.constructed() as instance:
            data = instance.get_val_at(val_path)
        return cls(data)

    @property
    def econtent_val(self) -> typing.Any:
        """Extract the eContent value."""
        with self.constructed() as instance:
            val = instance.get_val_at(["eContent"])
        if isinstance(val, tuple):
            return val[1][1]
        else:
            return val
