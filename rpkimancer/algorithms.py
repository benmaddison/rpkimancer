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
"""Message digest algoritms used in rpkimancer library."""

from __future__ import annotations

import hashlib
import logging
import typing

log = logging.getLogger(__name__)


DigestAlgorithm = typing.Callable[[bytes], "hashlib._Hash"]
AlgorithmDict = typing.Dict[typing.Tuple[int, ...], DigestAlgorithm]

SHA256: typing.Final = (2, 16, 840, 1, 101, 3, 4, 2, 1)

DIGEST_ALGORITHMS: typing.Final[AlgorithmDict] = {SHA256: hashlib.sha256}
