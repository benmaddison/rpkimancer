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
"""ASN.1 data types and helpers."""
from __future__ import annotations

import contextlib
import logging
import typing

from .types import ASN1Obj, ASN1ObjData
from ..utils import LogWriter

log = logging.getLogger(__name__)


def log_level_parser(line: str) -> int:
    """Determine the correct log level by parsing the message."""
    if line.startswith("WNG:"):
        return logging.WARNING
    else:
        return logging.INFO


log_writer = LogWriter(log, level_cb=log_level_parser)

ContentSubclass = typing.TypeVar("ContentSubclass",
                                 bound="Content")


class Content:
    """Generic base ASN.1 type wrapping pycrates API."""

    content_syntax: ASN1Obj

    def __init__(self, data: typing.Any) -> None:
        """Initialise the instance from python data."""
        log.debug(f"starting initialisation of {self}")
        with self.constructed(data) as instance:
            self._content_data = instance.get_val()
        log.debug(f"finished initialisation of {self}")

    @classmethod
    def from_der(cls: typing.Type[ContentSubclass],
                 der_data: bytes) -> ContentSubclass:
        """Construct an instance from DER encoded data."""
        log.debug(f"deserialising {cls} object from DER data.")
        with log_writer.redirect_stdout():
            cls.content_syntax.from_der(der_data)
        data = cls.content_syntax.get_val()
        cls.content_syntax.reset_val()
        log.debug(f"finished deserialising {cls} object")
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
            log.debug(f"serialising object {self} to ASN.1 data encoding")
            with log_writer.redirect_stdout():
                val = instance.to_asn1()
            log.debug(f"finished serialising object {self}")
        return typing.cast(str, val)

    def to_der(self) -> bytes:
        """Serialize as DER."""
        with self.constructed() as instance:
            log.debug(f"serialising object {self} to DER")
            with log_writer.redirect_stdout():
                val = instance.to_der()
            log.debug(f"finished serialising object {self}")
        return typing.cast(bytes, val)
