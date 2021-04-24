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
"""RPKI SignedObject implementations."""

from __future__ import annotations

import importlib.metadata
import logging
import typing

from . import base, gbr, mft, roa

log = logging.getLogger(__name__)

SignedObject = base.SignedObject

SignedObjectSubclass = typing.TypeVar("SignedObjectSubclass",
                                      bound=SignedObject)

RpkiGhostbusters = gbr.RpkiGhostbusters
RpkiManifest = mft.RpkiManifest
RouteOriginAttestation = roa.RouteOriginAttestation


def from_ext(ext: str) -> typing.Type[SignedObject]:
    """Get a SignedObject by file extension."""
    object_types = [RpkiGhostbusters, RpkiManifest, RouteOriginAttestation]
    entry_point_name = "rpkimancer.sigobj"
    entry_points = importlib.metadata.entry_points()
    for entry_point in entry_points.get(entry_point_name, []):
        log.info(f"trying to load signed object {entry_point.value}")
        cls = entry_point.load()
        if issubclass(cls, SignedObject):
            object_types.append(cls)
        else:
            log.warning(f"signed objects must inherit from {SignedObject}")
    lookup_map = {cls.econtent_cls.file_ext: cls
                  for cls in object_types}
    try:
        return lookup_map[ext]
    except KeyError:
        return lookup_map[ext.lstrip(".")]
