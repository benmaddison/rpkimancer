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
"""RPKI Ghostbusters Record implementation - RFC6493."""

from __future__ import annotations

import json
import logging
import typing

from .base import EncapsulatedContent, SignedObject
from ..asn1.mod import RPKIGhostbusters
from ..resources import INHERIT_AS, INHERIT_IPV4, INHERIT_IPV6

log = logging.getLogger(__name__)


class RpkiGhostbustersEContent(EncapsulatedContent):
    """encapContentInfo for RPKI Ghostbusters Record - RFC6493."""

    content_type = RPKIGhostbusters.id_ct_rpkiGhostbusters
    content_syntax = RPKIGhostbusters.GhostbustersRecord
    file_ext = "gbr"
    as_resources = INHERIT_AS
    ip_resources = [INHERIT_IPV4, INHERIT_IPV6]

    def __init__(self,
                 full_name: str,
                 org: typing.Optional[str] = None,
                 address: typing.Optional[str] = None,
                 tel: typing.Optional[str] = None,
                 email: typing.Optional[str] = None) -> None:
        """Initialise the encapContentInfo."""
        log.info(f"preparing data for {self}")
        vcard = "BEGIN:VCARD\r\n"
        vcard += "VERSION:4.0\r\n"
        vcard += f"FN:{full_name}\r\n"
        if org is not None:
            vcard += f"ORG:{org}\r\n"
        if address is not None:
            vcard += f"ADR:{address}\r\n"
        if tel is not None:
            vcard += f"TEL;VALUE=uri:tel:{tel}\r\n"
        if email is not None:
            vcard += f"EMAIL:{email}\r\n"
        vcard += "END:VCARD"
        data = vcard.encode()
        super().__init__(data)

    def to_txt(self) -> str:
        """Get default text serialization."""
        return typing.cast(str, self.content_data.decode())

    def to_json(self) -> str:
        """Serialize as JSON."""
        vcard = self.to_txt()
        data = dict()
        for line in vcard.splitlines():
            key, val = line.split(":", 1)
            if key in ("BEGIN", "END"):
                continue
            data[key.lower()] = val
        return json.dumps(data, indent=2)


class RpkiGhostbusters(SignedObject,
                       econtent_type=RPKIGhostbusters.ct_rpkiGhostbusters):
    """CMS ASN.1 ContentInfo for RPKI Ghostbusters Records."""

    econtent_cls = RpkiGhostbustersEContent
