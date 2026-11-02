"""Internal authority-storage boundary; unsupported platforms never create state.

Importing an optional authority module does not select a backend. Each backend
must qualify the complete storage and locking contract before it is registered;
availability of a file-lock implementation alone is not sufficient.
"""

from __future__ import annotations

import os
from functools import cache
from pathlib import Path
from typing import Protocol

from ._errors import StateError


class Backend(Protocol):
    """A backend owns every platform-dependent authority operation.

    Opens return ordinary Python file descriptors, closed by their caller. Locks
    live until the descriptor is closed, exclude independent processes and retain
    shared/exclusive semantics. Nonblocking contention raises BlockingIOError.
    Writes and removals complete only after the directory entry is durable.
    """

    def directory(self, path: Path) -> None: ...

    def private_open(self, path: Path, flags: int) -> int: ...

    def atomic_write(self, path: Path, raw: bytes) -> None: ...

    def durable_unlink(self, path: Path) -> None: ...

    def lock(self, fd: int, *, exclusive: bool, blocking: bool) -> None: ...


@cache
def _select_backend(platform: str) -> Backend:
    if platform != "posix":
        raise StateError("unsupported_storage_platform")
    # Keep fcntl, ownership, no-follow and directory durability inside a single
    # qualified implementation. In particular, never fall back to a thread lock.
    from ._posix import PosixBackend

    return PosixBackend()


def backend() -> Backend:
    return _select_backend(os.name)
