"""The qualified POSIX authority-storage implementation."""

from __future__ import annotations

import contextlib
import fcntl
import os
import stat
import tempfile
from pathlib import Path

from ._errors import StateError


class PosixBackend:
    def directory(self, path: Path) -> None:
        """Require owned directories without following a symlink at any component."""
        path = path.absolute()
        for part in reversed((path, *path.parents)):
            if part == Path(part.anchor):
                continue
            with contextlib.suppress(FileExistsError):
                part.mkdir(mode=0o700)
            info = part.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise StateError()
        info = path.lstat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise StateError()

    def private_open(self, path: Path, flags: int) -> int:
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            os.close(fd)
            raise StateError()
        return fd

    def _sync_directory(self, path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def atomic_write(self, path: Path, raw: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".record-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            self._sync_directory(path.parent)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)

    def durable_unlink(self, path: Path) -> None:
        path.unlink()
        self._sync_directory(path.parent)

    def lock(self, fd: int, *, exclusive: bool, blocking: bool) -> None:
        flags = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            flags |= fcntl.LOCK_NB
        fcntl.flock(fd, flags)
