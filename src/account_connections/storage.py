"""Private POSIX control records. Reads never repair retained authority."""

from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import os
import re
import stat
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_KEY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
MAX_RECORD = 2 * 1024 * 1024


class StateError(Exception):
    """Missing, unreadable or stale authority; hosts map this to a closed error."""

    def __init__(self, code: str = "connection_disconnected"):
        self.code = code
        super().__init__(code)


def identifier(value: str) -> str:
    if not isinstance(value, str) or not _KEY.fullmatch(value) or value in (".", ".."):
        raise ValueError("invalid record identifier")
    return value


def directory(path: Path) -> None:
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


def private_open(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(fd)
        raise StateError()
    return fd


def read_json(path: Path) -> Any:
    fd = private_open(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_RECORD + 1)
    if len(raw) > MAX_RECORD:
        raise StateError()

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise StateError()
            value[key] = item
        return value

    try:
        return json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, TypeError, RecursionError):
        raise StateError() from None


def atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_RECORD:
        raise StateError()
    fd, temporary = tempfile.mkstemp(prefix=".record-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class Store:
    """One independent file per person; one short process-safe authority lock.

    Initialization markers precede records. A crash in between is stopped, never
    reconstructed around credentials. Explicit migration is the only repair path.
    Do not hold a transaction across provider/browser work.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        directory(self.root)
        self._local = threading.local()
        self._thread_lock = threading.RLock()

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        with self._thread_lock:
            if getattr(self._local, "locked", False):
                yield
                return
            fd = private_open(self.root / ".authority.lock", os.O_CREAT | os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._local.locked = True
                yield
            finally:
                self._local.locked = False
                os.close(fd)

    def path(self, person: str) -> Path:
        return self.root / (identifier(person) + ".json")

    def marker(self, person: str) -> Path:
        return self.root / (identifier(person) + ".initialized")

    def exists(self, person: str) -> bool:
        return any(
            os.path.lexists(path)
            for path in (
                self.path(person),
                self.marker(person),
                self.root / ".snapshots" / (identifier(person) + ".json"),
                self.root / ".migrations" / (identifier(person) + ".json"),
            )
        )

    def read(self, person: str) -> dict[str, Any]:
        try:
            directory(self.root)
            migration = self.root / ".migrations" / (identifier(person) + ".json")
            if os.path.lexists(migration):
                directory(migration.parent)
                receipt = read_json(migration)
                if not isinstance(receipt, dict) or receipt.get("state") != "complete":
                    raise StateError()
            data = read_json(self.path(person))
            if (
                not isinstance(data, dict)
                or data.get("version") != 3
                or data.get("person") != person
            ):
                raise StateError()
            return data
        except (OSError, ValueError, TypeError):
            raise StateError() from None

    def write(self, person: str, data: dict[str, Any]) -> None:
        if not getattr(self._local, "locked", False):
            raise RuntimeError("authority lock required")
        if not os.path.lexists(self.marker(person)):
            atomic_json(self.marker(person), {"version": 3})
        atomic_json(self.path(person), data)

    @contextlib.contextmanager
    def edit(self, person: str) -> Iterator[dict[str, Any]]:
        with self.lock():
            data = copy.deepcopy(self.read(person))
            yield data
            self.write(person, data)

    def people(self) -> list[str]:
        """Include marked people with lost records so offers can report damage."""
        return sorted(
            {
                p.stem
                for p in self.root.iterdir()
                if p.suffix in (".json", ".initialized") and _KEY.fullmatch(p.stem)
            }
        )
