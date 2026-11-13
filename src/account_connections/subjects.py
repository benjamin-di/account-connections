"""Durable issuer/subject resolution; admission and provider state stay with the host."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterable
from typing import Any, cast

from .people import MAX_NAMESPACES, MAX_PEOPLE, Identity, People
from .storage import StateError, atomic_json, identifier, read_json
from .storage import directory as private_directory


def _key(identity: Identity) -> str:
    if not isinstance(identity, Identity):
        raise ValueError("verified immutable identity required")
    raw = json.dumps([identity.issuer, identity.subject], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


class Subjects:
    """Map a verified identity to its retained person, or a new empty person.

    Enable once at installation/migration with complete, independently verified
    legacy bindings. An empty binding list is valid only for a proven empty
    installation. Routine requests never scan other people's controls or infer
    ownership from an alias, name, email or provider credential.

    Resolution is not admission: hosts must verify identity and eligibility
    before calling, then call People.contact with current admission/readmission
    evidence. Returning a departed person's identifier does not reactivate them.
    """

    def __init__(self, people: People):
        self.people = people
        self.path = people.store.root / ".subjects.json"
        self.marker = people.store.root / ".subjects.initialized"

    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            marker = read_json(self.marker)
            if (
                not isinstance(marker, dict)
                or marker != {"version": 1}
                or type(marker["version"]) is not int
            ):
                raise StateError()
            value = read_json(self.path)
            if (
                not isinstance(value, dict)
                or set(value) != {"version", "owners"}
                or type(value["version"]) is not int
                or value["version"] != 1
                or not isinstance(value["owners"], dict)
                or len(value["owners"]) > MAX_PEOPLE
            ):
                raise StateError()
            persons = set()
            for key, row in value["owners"].items():
                if not isinstance(row, dict) or set(row) != {
                    "identity",
                    "person",
                    "state",
                    "namespaces",
                }:
                    raise StateError()
                binding = row["identity"]
                if not isinstance(binding, dict) or set(binding) != {"issuer", "sub"}:
                    raise StateError()
                identity = Identity(binding["issuer"], binding["sub"])
                if key != _key(identity) or row["person"] in persons:
                    raise StateError()
                persons.add(identifier(row["person"]))
                if row["state"] not in ("pending", "ready"):
                    raise StateError()
                namespaces = row["namespaces"]
                if (
                    not isinstance(namespaces, list)
                    or len(namespaces) > MAX_NAMESPACES
                    or namespaces != sorted(set(namespaces))
                ):
                    raise StateError()
                for namespace in namespaces:
                    identifier(namespace)
            return cast(dict[str, dict[str, Any]], value["owners"])
        except (OSError, ValueError, TypeError, KeyError):
            raise StateError("subject_index_unavailable") from None

    def _write(self, owners: dict[str, dict[str, Any]]) -> None:
        atomic_json(self.path, {"version": 1, "owners": owners})

    def lookup(self, identity: Identity) -> str | None:
        """Find a completed binding without allocation or admission.

        Use for ordinary browser sessions and verified lost-group callbacks.
        Unknown or unfinished allocations return None; lost marked authority
        refuses. This permits departure of an existing owner without enrolling
        a newly denied identity.
        """
        key = _key(identity)
        with self.people.store.lock():
            row = self._read().get(key)
            if row is None or row["state"] != "ready":
                return None
            if row["identity"] != identity.record():
                raise StateError("identity_mismatch")
            person = row["person"]
            data = self.people.read(person)
            if data["identity"] not in (None, identity.record()):
                raise StateError("identity_mismatch")
            stopped = self.people._inactive(person)
            if stopped and stopped["identity"] not in (None, identity.record()):
                raise StateError("identity_mismatch")
            return cast(str, person)

    def initialize(
        self,
        bindings: Iterable[tuple[Identity, str]],
        *,
        retained_credentials: bool,
    ) -> None:
        """Operator migration, never a login action; does not alter existing records.

        Hosts must census external provider/initialization state. If it exists,
        their retained controls must already be present and fully mapped. Passing
        retained_credentials=True refuses an empty installation. A completed
        index cannot be replaced, even by another migration invocation.
        """
        if type(retained_credentials) is not bool:
            raise ValueError("retained credential census required")
        owners: dict[str, dict[str, Any]] = {}
        persons = set()
        for identity, person in bindings:
            key = _key(identity)
            identifier(person)
            if key in owners or person in persons:
                raise StateError("identity_mismatch")
            persons.add(person)
            owners[key] = {
                "identity": identity.record(),
                "person": person,
                "state": "ready",
                "namespaces": [],
            }
        if len(owners) > MAX_PEOPLE:
            raise StateError("person_limit")
        with self.people.store.lock():
            if os.path.lexists(self.marker):
                if self._read() != owners:
                    raise StateError("subject_index_already_initialized")
                return
            known = set(self.people.store.people())
            # Native migration intent/snapshots may precede both the canonical
            # record and its marker. Their owners are retained authority too.
            for name in (".inactive", ".migrations", ".snapshots"):
                folder = self.people.store.root / name
                if not os.path.lexists(folder):
                    continue
                private_directory(folder)
                for path in folder.iterdir():
                    if path.suffix != ".json":
                        raise StateError("subject_migration_required")
                    known.add(identifier(path.stem))
            if known != persons or retained_credentials and not known:
                raise StateError("subject_migration_required")
            for row in owners.values():
                person = row["person"]
                stopped = self.people._inactive(person)
                if stopped and stopped["identity"] not in (None, row["identity"]):
                    raise StateError("identity_mismatch")
                if self.people.store.exists(person):
                    data = self.people.read(person)
                    if data["identity"] not in (None, row["identity"]):
                        raise StateError("identity_mismatch")
                else:
                    raise StateError("subject_migration_required")
            # An interrupted explicit migration may finish only its exact plan.
            if os.path.lexists(self.path):
                if read_json(self.path) != {"version": 1, "owners": owners}:
                    raise StateError("subject_index_unavailable")
            else:
                self._write(owners)
            atomic_json(self.marker, {"version": 1})

    def resolve(
        self,
        identity: Identity,
        *,
        namespaces: Iterable[str],
        retained_credentials: Callable[[str], bool],
    ) -> str:
        """Resolve without aliases or implicit selection; never clear departure.

        The host callback checks local provider state for this exact person
        under the authority lock; it must not perform network/browser work.
        A pending publication is retried only when its retained authority proves
        the same identity and still-empty namespace state. Missing marked records
        or an unavailable index refuse; neither is reconstructed.
        """
        key = _key(identity)
        requested = sorted(set(namespaces))
        if len(requested) > MAX_NAMESPACES or not callable(retained_credentials):
            raise ValueError("bounded namespaces and retained credential census required")
        for namespace in requested:
            identifier(namespace)
        with self.people.store.lock():
            owners = self._read()
            row = owners.get(key)
            retained = False
            if row is None or row["state"] == "pending":
                person = row["person"] if row else "p" + key[:31]
                retained = retained_credentials(person)
                if type(retained) is not bool:
                    raise ValueError("retained credential census must return a boolean")
            if row is None:
                person = "p" + key[:31]
                if (
                    retained
                    or len(owners) >= MAX_PEOPLE
                    or self.people.store.exists(person)
                    or self.people._inactive(person) is not None
                    or any(owner["person"] == person for owner in owners.values())
                ):
                    raise StateError("subject_enrollment_refused")
                row = {
                    "identity": identity.record(),
                    "person": person,
                    "state": "pending",
                    "namespaces": requested,
                }
                owners[key] = row
                self._write(owners)
            if row["identity"] != identity.record():
                raise StateError("identity_mismatch")
            person = row["person"]
            stopped = self.people._inactive(person)
            if stopped is not None and stopped["identity"] not in (None, identity.record()):
                raise StateError("identity_mismatch")
            if row["state"] == "pending":
                if retained or stopped is not None or row["namespaces"] != requested:
                    raise StateError("subject_enrollment_refused")
                if self.people.store.exists(person):
                    data = self.people.read(person)
                else:
                    data = self.people.enroll(person, namespaces=requested, identity=identity)
                if data["identity"] != identity.record() or set(data["namespaces"]) != set(
                    requested
                ):
                    raise StateError("identity_mismatch")
                for namespace in data["namespaces"].values():
                    control = namespace["control"]
                    if (
                        control["state"] != "disconnected"
                        or control["generation"] != 0
                        or control["human_until"] != 0
                        or control["attempt"] is not None
                        or namespace["shares"]
                        or namespace["selection"]["choice"] is not None
                        or namespace["metadata"]
                    ):
                        raise StateError("subject_enrollment_refused")
                row["state"] = "ready"
                self._write(owners)
            elif self.people.store.exists(person):
                data = self.people.read(person)
                if data["identity"] not in (None, identity.record()):
                    raise StateError("identity_mismatch")
                if not set(requested) <= set(data["namespaces"]):
                    raise StateError("namespace_migration_required")
            else:
                raise StateError("subject_authority_missing")
            return cast(str, person)
