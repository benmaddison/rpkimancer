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
import io
import logging
import typing

log = logging.getLogger(__name__)

LogLevelCallback = typing.Callable[[str], int]


class LogWriter(io.TextIOBase):
    """File-like object for stream-to-log redirection."""

    def __init__(self,
                 logger: logging.Logger,
                 level: int = logging.INFO,
                 level_cb: typing.Optional[LogLevelCallback] = None) -> None:
        """Initialise the LogWriter."""
        self.logger = logger
        if level_cb is not None:
            self.level_cb = level_cb
        else:
            self.level_cb = lambda line: level

    def detach(self) -> typing.BinaryIO:
        """Detatch the underlying binary buffer."""
        raise io.UnsupportedOperation

    def read(self, size: typing.Optional[int] = -1) -> str:
        """Read from the text stream."""
        raise io.UnsupportedOperation

    def write(self, s: str) -> int:
        """Write the contents of a buffer to the stream."""
        written = 0
        for line in s.rstrip().splitlines():
            level = self.level_cb(line)
            msg = line.strip()
            self.logger.log(level, msg)
            written += len(msg)
        return written

    def redirect_stdout(self) -> typing.ContextManager[typing.Any]:
        """Return a context manager to redirect stdout."""
        return contextlib.redirect_stdout(self)
