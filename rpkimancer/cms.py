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
import contextlib

from .asn1 import (CryptographicMessageSyntax_2009,
                   PKIX1Explicit_2009)


class Content:

    content_syntax = None

    def __init__(self, data):
        with self.constructed(data) as instance:
            self._content_data = instance.get_val()

    @classmethod
    def from_der(cls, der_data):
        cls.content_syntax.from_der(der_data)
        data = cls.content_syntax.get_val()
        cls.content_syntax.reset_val()
        return cls(data)

    @property
    def content_data(self):
        return self._content_data

    @contextlib.contextmanager
    def constructed(self, data=None):
        if data is None:
            data = self.content_data
        try:
            self.content_syntax.set_val(data)
            yield self.content_syntax
        finally:
            self.content_syntax.reset_val()

    def to_asn1(self):
        with self.constructed() as instance:
            return instance.to_asn1()

    def to_der(self):
        with self.constructed() as instance:
            return instance.to_der()


class ContentData(Content):

    content_type = None


class ContentInfo(Content):

    content_syntax = CryptographicMessageSyntax_2009.ContentInfo

    def __init__(self, content: ContentData):
        content_type_oid = content.content_type.get_val()
        content_type_name = content.content_syntax.fullname()
        content_data = content.content_data
        data = {"contentType": content_type_oid,
                "content": (content_type_name, content_data)}
        super().__init__(data)


class SignedData(ContentData):

    content_type = CryptographicMessageSyntax_2009.id_signedData
    content_syntax = CryptographicMessageSyntax_2009.SignedData


class Certificate(Content):

    content_syntax = PKIX1Explicit_2009.Certificate

    @property
    def subject_public_key_info(self):
        with self.constructed() as instance:
            data = instance.get_val_at(["toBeSigned", "subjectPublicKeyInfo"])
        return SubjectPublicKeyInfo(data)


class SubjectPublicKeyInfo(Content):

    content_syntax = PKIX1Explicit_2009.SubjectPublicKeyInfo


class SignedAttributes(Content):

    content_syntax = CryptographicMessageSyntax_2009.SignedAttributes

    def __init__(self, content_type, message_digest):
        ct_attr_oid = CryptographicMessageSyntax_2009.id_contentType.get_val()
        md_attr_oid = CryptographicMessageSyntax_2009.id_messageDigest.get_val()
        data = [
            {
                "attrType": ct_attr_oid,
                "attrValues": [('ContentType', content_type)]
            },
            {
                "attrType": md_attr_oid,
                "attrValues": [('MessageDigest', message_digest)]
            }
        ]
        super().__init__(data)
