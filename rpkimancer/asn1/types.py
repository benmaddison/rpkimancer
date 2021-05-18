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
"""Compile and re-export the provided ASN.1 modules."""
from __future__ import annotations

import logging
import typing

import pycrate_asn1rt.asnobj as _asn1_object_types
import pycrate_asn1rt.asnobj_basic as _asn1_basic_types
import pycrate_asn1rt.asnobj_class as _asn1_class_types

log = logging.getLogger(__name__)

ASN1Obj = _asn1_object_types.ASN1Obj
ASN1ObjData = typing.Any
OID = _asn1_basic_types.OID
ASN1Class = _asn1_class_types.CLASS
