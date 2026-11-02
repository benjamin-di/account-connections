"""Durable lifecycle barriers and credential-writer fences, without credentials."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any, cast

from .people import People
from .rules import revision
from .storage import StateError, directory, lock_fd, private_open


class Controls:
    def __init__(self, people: People):
        self.people, self.store, self.clock = people, people.store, people.clock
        self._local = threading.local()

    def status(self, owner: str, namespace: str) -> dict[str, Any]:
        return cast(dict[str, Any], self.people.namespace(owner, namespace)["control"])

    @contextlib.contextmanager
    def _edit(self, owner: str, namespace: str) -> Iterator[dict[str, Any]]:
        with self.store.lock():
            data = self.people.read(owner)
            try:
                control = data["namespaces"][namespace]["control"]
            except KeyError:
                raise StateError() from None
            yield control
            self.store.write(owner, data)

    def require_active(
        self,
        owner: str,
        namespace: str,
        *,
        epoch: str | None = None,
    ) -> dict[str, Any]:
        self.people.require_admitted(owner)
        control = self.status(owner, namespace)
        if control["state"] != "active" or epoch is not None and control["epoch"] != epoch:
            raise StateError("owner_reconnect")
        return control

    def maintenance_blocker(self, owner: str, namespace: str) -> str | None:
        self.people.require_admitted(owner)
        value = self.status(owner, namespace)
        if value["state"] != "active":
            return "connection_disconnected"
        if value["human_until"] > self.clock():
            return "connection_interactive"
        return None

    def require_maintenance(self, owner: str, namespace: str) -> None:
        blocker = self.maintenance_blocker(owner, namespace)
        if blocker:
            raise StateError(blocker)

    @contextlib.contextmanager
    def operation(
        self,
        owner: str,
        namespace: str,
        *,
        exclusive: bool = True,
        timeout: float = 10,
    ) -> Iterator[None]:
        """Cross-process credential borrow/drain lock. Never upgrade a read borrow."""
        # Validate identifiers and namespace existence before deriving a lock key.
        self.people.namespace(owner, namespace)
        key = hashlib.sha256((owner + "\0" + namespace).encode()).hexdigest()
        held = getattr(self._local, "held", {})
        if key in held:
            if exclusive and not held[key]:
                raise StateError("publication_requires_exclusive")
            yield
            return
        root = self.store.root / ".operations"
        directory(root)
        fd = private_open(root / (key + ".lock"), os.O_CREAT | os.O_RDWR)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    lock_fd(fd, exclusive=exclusive, blocking=False)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise StateError("connection_busy") from None
                    time.sleep(0.01)
            self._local.held = {**held, key: exclusive}
            yield
        finally:
            self._local.held = held
            os.close(fd)

    @contextlib.contextmanager
    def admitted(
        self,
        owner: str,
        namespace: str,
        *,
        epoch: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """New work stops at suspension; admitted work drains on its captured owner."""
        self.require_active(owner, namespace, epoch=epoch)
        with self.operation(owner, namespace, exclusive=False):
            with self.store.lock():
                captured = copy.deepcopy(self.require_active(owner, namespace, epoch=epoch))
            yield captured

    def begin(self, owner: str, namespace: str, *, ttl: float = 1200) -> str:
        if not 0 < ttl <= 3600:
            raise ValueError("bounded positive attempt lifetime required")
        with self._edit(owner, namespace) as value:
            self.people.require_admitted(owner)
            if value["state"] == "disconnecting":
                raise StateError()
            value["revision"] = revision()
            if value["state"] != "active":
                value["state"] = "reconnecting"
            value["human_until"] = self.clock() + ttl
            value["attempt"] = {
                "revision": value["revision"],
                "staged": False,
                "expires": value["human_until"],
            }
            return str(value["revision"])

    def current(self, owner: str, namespace: str, expected: str) -> bool:
        value = self.status(owner, namespace)
        return bool(
            value["state"] in ("active", "reconnecting")
            and value["revision"] == expected
            and value["attempt"] is not None
            and value["attempt"]["expires"] > self.clock()
        )

    def _attempt(self, owner: str, namespace: str, expected: str) -> dict[str, Any]:
        self.people.require_admitted(owner)
        if not self.current(owner, namespace, expected):
            raise StateError("account_changed")
        return self.status(owner, namespace)

    def started(self, owner: str, namespace: str, expected: str, *, ttl: float = 1200) -> None:
        if not 0 < ttl <= 3600:
            raise ValueError("bounded positive attempt lifetime required")
        with self._edit(owner, namespace) as value:
            self._attempt(owner, namespace, expected)
            value["human_until"] = self.clock() + ttl
            value["attempt"]["expires"] = value["human_until"]

    def stage(
        self,
        owner: str,
        namespace: str,
        expected: str,
        writer: Callable[[], None],
    ) -> None:
        """The host stages credential bytes; only a completion flag is retained here."""
        with self.operation(owner, namespace), self._edit(owner, namespace) as value:
            self._attempt(owner, namespace, expected)
            writer()
            value["attempt"]["staged"] = True

    def pending(self, owner: str, namespace: str) -> dict[str, Any] | None:
        value = self.status(owner, namespace)
        if not self.current(owner, namespace, value["revision"]):
            return None
        return copy.deepcopy(value["attempt"]) if value["attempt"]["staged"] else None

    def cancel(self, owner: str, namespace: str, expected: str) -> bool:
        value = self.status(owner, namespace)
        if value["state"] == "disconnecting" or value["revision"] != expected:
            return False
        with self.operation(owner, namespace), self._edit(owner, namespace) as value:
            if value["state"] == "disconnecting" or value["revision"] != expected:
                return False
            value.update(revision=revision(), human_until=0, attempt=None)
            if value["state"] == "reconnecting":
                value["state"] = "disconnected"
            return True

    def publish(
        self,
        owner: str,
        namespace: str,
        expected: str,
        writer: Callable[[], None],
        *,
        generation: int | None = None,
        require_staged: bool = True,
    ) -> str:
        """Fence the final verified writer. Interrupted publication remains stopped.

        A write-ahead reconnect barrier commits before the app writer runs, so a
        crash after credential replacement cannot expose it under an older epoch.
        The host must independently verify provider identity and entitlement.
        """
        with self.operation(owner, namespace), self.store.lock():
            value = self._attempt(owner, namespace, expected)
            if require_staged and not value["attempt"]["staged"]:
                raise StateError("account_changed")
            if generation is not None and (
                type(generation) is not int or generation <= value["generation"]
            ):
                raise StateError("account_changed")
            data = self.people.read(owner)
            value = data["namespaces"][namespace]["control"]
            value.update(state="reconnecting", epoch=revision())
            self.store.write(owner, data)
            writer()
            value.update(
                state="active",
                revision=revision(),
                epoch=revision(),
                human_until=0,
                attempt=None,
                generation=generation if generation is not None else value["generation"] + 1,
            )
            self.store.write(owner, data)
            return str(value["epoch"])

    def maintain(
        self,
        owner: str,
        namespace: str,
        epoch: str,
        writer: Callable[[], None],
    ) -> None:
        """Fence native cookie refresh against a human attempt and lifecycle barrier."""
        with self.operation(owner, namespace), self.store.lock():
            self.require_active(owner, namespace, epoch=epoch)
            self.require_maintenance(owner, namespace)
            writer()

    def suspend(self, owner: str, namespace: str, *, expected: str | None = None) -> str | None:
        """Commit the barrier immediately; no credential borrow lock is needed."""
        with self._edit(owner, namespace) as value:
            if expected is not None and value["revision"] != expected:
                return None
            value.update(
                revision=revision(),
                epoch=revision(),
                state="disconnecting",
                human_until=0,
                attempt=None,
            )
            return str(value["revision"])

    def finish_disconnect(
        self,
        owner: str,
        namespace: str,
        expected: str,
        delete: Callable[[], None],
        *,
        timeout: float = 10,
    ) -> bool:
        value = self.status(owner, namespace)
        if value["state"] != "disconnecting" or value["revision"] != expected:
            return False
        with self.operation(owner, namespace, timeout=timeout):
            with self.store.lock():
                value = self.status(owner, namespace)
                if value["state"] != "disconnecting" or value["revision"] != expected:
                    return False
            delete()
            with self.store.lock():
                data = self.people.read(owner)
                value = data["namespaces"][namespace]["control"]
                if value["state"] != "disconnecting" or value["revision"] != expected:
                    return False
                value.update(state="disconnected", revision=revision(), epoch=revision())
                self.store.write(owner, data)
                return True

    def disconnect(
        self,
        owner: str,
        namespace: str,
        delete: Callable[[], None],
        *,
        expected: str | None = None,
        cancel: Callable[[], None] | None = None,
        timeout: float = 10,
    ) -> bool:
        barrier = self.suspend(owner, namespace, expected=expected)
        if barrier is None:
            return False
        if cancel:
            cancel()
        return self.finish_disconnect(owner, namespace, barrier, delete, timeout=timeout)
