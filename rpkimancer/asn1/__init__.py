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

import contextlib
import glob
import logging
import os
import typing

import pycrate_asn1c.asnproc as _asn1_compile
import pycrate_asn1c.generator as _asn1_generate

from .types import ASN1Obj, ASN1ObjData

log = logging.getLogger(__name__)


ContentSubclass = typing.TypeVar("ContentSubclass",
                                 bound="Content")


class Content:
    """Generic base ASN.1 type wrapping pycrates API."""

    content_syntax: ASN1Obj

    def __init__(self, data: typing.Any) -> None:
        """Initialise the instance from python data."""
        with self.constructed(data) as instance:
            self._content_data = instance.get_val()

    @classmethod
    def from_der(cls: typing.Type[ContentSubclass],
                 der_data: bytes) -> ContentSubclass:
        """Construct an instance from DER encoded data."""
        cls.content_syntax.from_der(der_data)
        data = cls.content_syntax.get_val()
        cls.content_syntax.reset_val()
        return cls(data)

    @property
    def content_data(self) -> ASN1ObjData:
        """Get the underlying python data for this type instance."""
        return self._content_data

    @contextlib.contextmanager
    def constructed(self,
                    data: typing.Optional[ASN1ObjData] = None) -> ASN1Obj:
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
            val = instance.to_asn1()
        return typing.cast(str, val)

    def to_der(self) -> bytes:
        """Serialize as DER."""
        with self.constructed() as instance:
            val = instance.to_der()
        return typing.cast(bytes, val)


def _compile_modules() -> None:
    pkg_dir = os.path.dirname(__file__)
    mods_dir = os.path.join(pkg_dir, "modules")
    mods = list()
    for path in glob.glob(os.path.join(mods_dir, "**", "*.asn")):
        with open(path) as f:
            mods.append(f.read())
    _asn1_compile.compile_text(mods)
    output_path = os.path.join(pkg_dir, "_asn1.py")
    _asn1_generate.PycrateGenerator(dest=output_path)


_compile_modules()
from ._asn1 import *  # noqa
