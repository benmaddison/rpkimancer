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
from .base import EncapsulatedContent, SignedObject
from ..asn1 import RPKIGhostbusters
from ..resources import INHERIT_AS, INHERIT_IPV4, INHERIT_IPV6


class RpkiGhostbustersEContent(EncapsulatedContent):

    content_type = RPKIGhostbusters.id_ct_rpkiGhostbusters
    content_syntax = RPKIGhostbusters.GhostbustersRecord
    file_ext = "gbr"
    as_resources = INHERIT_AS
    ip_resources = [INHERIT_IPV4, INHERIT_IPV6]

    def __init__(self,
                 full_name: str,
                 org: str = None,
                 address: str = None,
                 tel: str = None,
                 email: str = None):
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


class RpkiGhostbusters(SignedObject):

    econtent_cls = RpkiGhostbustersEContent
