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

import contextlib
import typing

from .asn1 import (CryptographicMessageSyntax_2009,
                   PKIX1Explicit_2009)


class Content:
    """Generic base ASN.1 type wrapping pycrates API."""

    @property
    def content_syntax(self):
        """Get the pycrates object implementing the ASN.1 syntax for this type."""  # noqa: E501
        raise NotImplementedError

    def __init__(self, data: typing.Any):
        """Initialise the instance from python data."""
        with self.constructed(data) as instance:
            self._content_data = instance.get_val()

    @classmethod
    def from_der(cls, der_data):
        """Construct an instance from DER encoded data."""
        cls.content_syntax.from_der(der_data)
        data = cls.content_syntax.get_val()
        cls.content_syntax.reset_val()
        return cls(data)

    @property
    def content_data(self):
        """Get the underlying python data for this type instance."""
        return self._content_data

    @contextlib.contextmanager
    def constructed(self, data=None):
        """Provide a context manager to mediate the global pycrates object."""
        if data is None:
            data = self.content_data
        try:
            self.content_syntax.set_val(data)
            yield self.content_syntax
        finally:
            self.content_syntax.reset_val()

    def to_asn1(self) -> str:
        """Serialize as ASN.1 data."""
        with self.constructed() as instance:
            return instance.to_asn1()

    def to_der(self) -> bytes:
        """Serialize as DER."""
        with self.constructed() as instance:
            return instance.to_der()


class ContentData(Content):
    """Generic base class for ASN.1 types idenitied by an OID."""

    @property
    def content_type(self):
        """Get the pycrates object implementing the ASN.1 OID for this type."""
        raise NotImplementedError


class ContentInfo(Content):
    """CMS ASN.1 ContentInfo type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.ContentInfo

    def __init__(self, content: ContentData):
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


class Certificate(Content):
    """X.509 ASN.1 Certificate type - RFC5912."""

    content_syntax = PKIX1Explicit_2009.Certificate

    @property
    def subject_public_key_info(self):
        """Get the subjectPublicKeyInfo of the Certificate."""
        with self.constructed() as instance:
            data = instance.get_val_at(["toBeSigned", "subjectPublicKeyInfo"])
        return SubjectPublicKeyInfo(data)


class SubjectPublicKeyInfo(Content):
    """X.509 ASN.1 SubjectPublicKeyInfo type - RFC5912."""

    content_syntax = PKIX1Explicit_2009.SubjectPublicKeyInfo


class SignedAttributes(Content):
    """CMS ASN.1 SignedAttributes type - RFC5911."""

    content_syntax = CryptographicMessageSyntax_2009.SignedAttributes

    def __init__(self, content_type, message_digest):
        """Initialise the instance from an eContentType and eContent digest."""
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
