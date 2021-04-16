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
"""Object Identifiers used in RPKI Resource Certificates."""

from __future__ import annotations

import typing

from cryptography import x509


AIA_CA_ISSUERS_OID: typing.Final = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS  # noqa: E501
SIA_CA_REPOSITORY_OID: typing.Final = x509.oid.SubjectInformationAccessOID.CA_REPOSITORY  # noqa: E501
SIA_MFT_ACCESS_OID: typing.Final = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.10")
SIA_OBJ_ACCESS_OID: typing.Final = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.11")
RPKI_CERT_POLICY_OID: typing.Final = x509.ObjectIdentifier("1.3.6.1.5.5.7.14.2")  # noqa: E501
IP_RESOURCES_OID: typing.Final = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.7")
AS_RESOURCES_OID: typing.Final = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.8")
