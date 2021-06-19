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
"""RPKI Foo Object."""

from __future__ import annotations

import logging

from rpkimancer.asn1.mod import RpkiFoo
from rpkimancer.resources import INHERIT_AS, INHERIT_IPV4, INHERIT_IPV6
from rpkimancer.sigobj.base import EncapsulatedContentType, SignedObject

log = logging.getLogger(__name__)


class FooObjectContentType(EncapsulatedContentType):
    """encapContentInfo for RPKI Foo Objects."""

    asn1_definition = RpkiFoo.ct_rpkiFooObject
    file_ext = "foo"
    as_resources = INHERIT_AS
    ip_resources = [INHERIT_IPV4, INHERIT_IPV6]

    def __init__(self, content: str) -> None:
        """Initialise the encapContentInfo."""
        data = content.encode()
        super().__init__(data)


class FooObject(SignedObject[FooObjectContentType]):
    """CMS ASN.1 ContentInfo for RPKI Foo Objects."""
