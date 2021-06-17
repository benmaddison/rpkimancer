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
import threading
import typing

import pycrate_asn1rt.init

from .types import ASN1Class, ASN1Obj, ASN1ObjData
from ..utils import LogWriter

log = logging.getLogger(__name__)

log_writer = LogWriter(log, level=logging.WARNING)

InterfaceSubclass = typing.TypeVar("InterfaceSubclass",
                                   bound="Interface")


def append_info_object_set(obj_set: ASN1Class, *obj_ins: ASN1Class) -> None:
    """Append an instance to an existing object information set at runtime."""
    for ins in obj_ins:
        log.info(f"Adding {obj_ins} to constraining object info set {obj_set}")
        obj_set.get_val().root.append(ins.get_val())
    log.info(f"re-building lookup table for {obj_set}")
    pycrate_asn1rt.init.build_classset_dict(obj_set)


class Interface:
    """Generic base ASN.1 type wrapping pycrates API."""

    content_syntax: ASN1Obj
    _lock = threading.Lock()

    @classmethod
    def __init_subclass__(cls, /, **kwargs: typing.Any) -> None:
        """Create a new lock for each subclass."""
        super().__init_subclass__(**kwargs)  # type: ignore[call-arg]
        cls._lock = threading.Lock()

    def __init__(self, data: typing.Any) -> None:
        """Initialise the instance from python data."""
        log.info(f"starting initialisation of {self} ASN.1 content")
        with self.constructed(data) as instance:
            self._content_data = instance.get_val()
        log.info(f"finished initialisation of {self} ASN.1 content")

    @classmethod
    def from_data(cls, data: typing.Any) -> InterfaceSubclass:
        """Construct an instance from python data."""
        log.info(f"creating new {cls} object")
        self: InterfaceSubclass = cls.__new__(cls)
        Interface.__init__(self, data)
        return self

    @classmethod
    def from_der(cls: typing.Type[InterfaceSubclass],
                 der_data: bytes) -> InterfaceSubclass:
        """Construct an instance from DER encoded data."""
        log.info(f"trying to acquire lock for {cls}")
        with cls._lock:
            log.info(f"deserialising {cls} object from DER data.")
            with log_writer.redirect_stdout():
                cls.content_syntax.from_der(der_data)
            data = cls.content_syntax.get_val()
            cls.content_syntax.reset_val()
            log.info(f"finished deserialising {cls} object")
        self: InterfaceSubclass = cls.__new__(cls)
        Interface.__init__(self, data)
        return self

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
        log.info(f"trying to acquire lock for {self.__class__}")
        with self._lock:
            log.debug(f"instantiating ASN1Obj from data: {data}")
            try:
                self.content_syntax.set_val(data)
                yield self.content_syntax
            finally:
                self.content_syntax.reset_val()

    def to_txt(self) -> str:
        """Get default text serialization."""
        return self.to_asn1()

    def to_asn1(self) -> str:
        """Serialize as ASN.1 data."""
        with self.constructed() as instance:
            log.info(f"serialising object {self} to ASN.1 data encoding")
            with log_writer.redirect_stdout():
                val = instance.to_asn1()
            log.info(f"finished serialising object {self}")
        return typing.cast(str, val)

    def to_der(self) -> bytes:
        """Serialize as DER."""
        with self.constructed() as instance:
            log.info(f"serialising object {self} to DER")
            with log_writer.redirect_stdout():
                val = instance.to_der()
            log.info(f"finished serialising object {self}")
        return typing.cast(bytes, val)

    def to_jer(self) -> str:
        """Serialize as JER."""
        with self.constructed() as instance:
            log.info(f"serialising object {self} to JSON")
            with log_writer.redirect_stdout():
                val = instance.to_jer()
            log.info(f"finished serialising object {self}")
        return typing.cast(str, val)

    def to_json(self) -> str:
        """Serialize as JSON."""
        return self.to_jer()

    def to_internal(self) -> str:
        """Serialize using internal python repr."""
        return f"{self.content_data!r}"
