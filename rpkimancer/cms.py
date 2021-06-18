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

from .algorithms import DigestAlgorithm
from .asn1 import Interface, append_info_object_set
from .asn1.mod import CryptographicMessageSyntax_2009
from .asn1.types import ASN1Class, ASN1Obj, OID

log = logging.getLogger(__name__)

CT = typing.TypeVar("CT", bound="ContentType")
ECT = typing.TypeVar("ECT", bound="ContentType")


class ContentInfo(Interface, typing.Generic[CT]):
    """CMS ASN.1 ContentInfo type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.ContentInfo

    def __init__(self, content: CT) -> None:
        """Initialise the instance from contained ContentData."""
        log.info(f"preparing data for {self}")
        content_type_oid = content.content_type
        content_type_name = content.content_syntax.fullname()
        content_data = content.content_data
        data = {"contentType": content_type_oid,
                "content": (content_type_name, content_data)}
        super().__init__(data)

    @classmethod
    def register_econtent_type(cls,
                               content_type: typing.Type[CT],
                               econtent_type: typing.Type[ECT]) -> None:
        """Add CONTENT-TYPE instance to eContentType constraint set."""
        content = cls.content_syntax.get_internals()["cont"]["content"]
        content_const_set = content.get_const()["tab"].get_val()
        content_type_oid = content_type.content_type
        content_data_inst = list(filter(lambda item: item["id"] == content_type_oid,  # noqa: E501
                                        content_const_set.getv()))[0]["Type"]
        encap_content_info = content_data_inst.get_internals()["cont"]["encapContentInfo"]  # noqa: E501
        econtent_open_type = encap_content_info.get_internals()["cont"]["eContentType"]  # noqa: E501
        econtent_const_set = econtent_open_type.get_const()["tab"]
        append_info_object_set(econtent_const_set,
                               econtent_type.asn1_definition)


class ContentTypeIdDescriptor:
    """Data descriptor for 'content_type' class property."""

    def __get__(self, instance: typing.Optional[CT],
                owner: typing.Type[CT]) -> OID:
        """Get CONTENT-TYPE.&id."""
        return owner.asn1_definition.get_val()["id"]


class ContentTypeSyntaxDescriptor:
    """Data descriptor for 'content_syntax' class property."""

    def __get__(self, instance: typing.Optional[CT],
                owner: typing.Type[CT]) -> ASN1Obj:
        """Get CONTENT-TYPE.&Type."""
        return owner.asn1_definition.get_val()["Type"].get_typeref()


class ContentType(Interface):
    """CMS ASN.1 CONTENT-TYPE instance - RFC5911."""

    asn1_definition: ASN1Class

    content_type = ContentTypeIdDescriptor()
    content_syntax = ContentTypeSyntaxDescriptor()


class SignedData(ContentType):
    """CMS ASN.1 ct-SignedData CONTENT-TYPE instance - RFC5911."""

    asn1_definition = CryptographicMessageSyntax_2009.ct_SignedData


class SignedAttributes(Interface):
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
                "attrValues": [('ContentType', content_type)],
            },
            {
                "attrType": md_attr_oid,
                "attrValues": [('MessageDigest', message_digest)],
            },
        ]
        super().__init__(data)


class EncapsulatedContentInfo(Interface, typing.Generic[CT]):
    """CMS ASN.1 EncapsulatedContentInfo type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.EncapsulatedContentInfo

    digest_algorithm: DigestAlgorithm

    def __init__(self, econtent: CT) -> None:
        """Initialise the instance from contained ContentData."""
        log.info(f"preparing data for {self}")
        data = {"eContentType": econtent.content_type,
                "eContent": econtent.to_der()}
        super().__init__(data)

    @classmethod
    def from_content_info(cls,
                          content_info: ContentInfo[SignedData]) -> EncapsulatedContentInfo[CT]:  # noqa: E501
        """De-encapsulate from ContentInfo instance."""
        val_path = ["content", "SignedData", "encapContentInfo"]
        with content_info.constructed() as instance:
            data = instance.get_val_at(val_path)
        return cls.from_data(data)

    @property
    def econtent_val(self) -> typing.Any:
        """Extract the eContent value."""
        with self.constructed() as instance:
            val = instance.get_val_at(["eContent"])
        if isinstance(val, tuple):
            return val[1][1]
        else:
            return val
