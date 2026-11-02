"""Pinned people and explicit, per-namespace grants and selections."""

from __future__ import annotations

import math
import os
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from . import rules
from .storage import StateError, Store, atomic_json, identifier, read_json
from .storage import directory as private_directory

MAX_PEOPLE = 100
MAX_NAMESPACES = 100
MAX_SHARES = 100


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str

    def __post_init__(self) -> None:
        if not all(isinstance(v, str) and 0 < len(v) <= 2048 for v in (self.issuer, self.subject)):
            raise ValueError("verified issuer and subject required")

    def record(self) -> dict[str, str]:
        return {"issuer": self.issuer, "sub": self.subject}


@dataclass(frozen=True)
class DirectoryPerson:
    """An exact-subject directory verdict, never a people-list or credential grant."""

    admitted: bool
    label: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.admitted) is not bool
            or self.label is not None
            and not isinstance(self.label, str)
        ):
            raise ValueError("directory verdict required")


Directory = Callable[[Identity], DirectoryPerson | None]


@dataclass(frozen=True)
class Person:
    id: str
    label: str
    active: bool
    available: bool


def _label(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("display label required")
    value = "".join(c for c in value if not unicodedata.category(c).startswith("C"))
    return " ".join(value.split())[:80].strip() or None


@dataclass(frozen=True)
class Policy:
    version: str
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        identifier(self.version)
        if not isinstance(self.capabilities, frozenset) or len(self.capabilities) > 100:
            raise ValueError("immutable bounded capabilities required")
        for item in self.capabilities:
            identifier(item)


def initial_namespace() -> dict[str, Any]:
    return {
        "control": {
            "revision": rules.revision(),
            "epoch": rules.revision(),
            "state": "disconnected",
            "generation": 0,
            "human_until": 0,
            "attempt": None,
        },
        "selection": {"choice": None, "revision": rules.revision()},
        "shares": {},
        "metadata": {},
    }


def selection(row: dict[str, Any]) -> rules.Selection:
    selected = row["selection"]
    choice = selected["choice"]
    return rules.Selection(
        rules.Choice(choice["owner"], choice["grant"]) if choice else None,
        selected["revision"],
    )


def save_selection(row: dict[str, Any], selected: rules.Selection) -> None:
    row["selection"] = {
        "choice": {"owner": selected.choice.owner, "grant": selected.choice.grant_revision}
        if selected.choice
        else None,
        "revision": selected.revision,
    }


def grant(value: dict[str, Any] | None, policy: Policy) -> rules.Grant | None:
    if value is None or value["policy"] != policy.version:
        return None
    capabilities = frozenset(value["capabilities"])
    if not capabilities <= policy.capabilities:
        return None
    return rules.Grant(value["revision"], capabilities)


def validate(data: dict[str, Any]) -> None:
    """Validate the entire authority record before using any of its decisions."""
    try:
        if set(data) != {"version", "person", "identity", "name", "namespaces"}:
            raise ValueError()
        if type(data["version"]) is not int or data["version"] != 3:
            raise ValueError()
        identifier(data["person"])
        identity = data["identity"]
        if identity is not None:
            if not isinstance(identity, dict) or set(identity) != {"issuer", "sub"}:
                raise ValueError()
            Identity(identity["issuer"], identity["sub"])
        if data["name"] is not None and (
            not isinstance(data["name"], str) or len(data["name"]) > 80
        ):
            raise ValueError()
        namespaces = data["namespaces"]
        if not isinstance(namespaces, dict) or len(namespaces) > MAX_NAMESPACES:
            raise ValueError()
        for namespace, row in namespaces.items():
            identifier(namespace)
            if not isinstance(row, dict) or set(row) != {
                "control",
                "selection",
                "shares",
                "metadata",
            }:
                raise ValueError()
            if not isinstance(row["metadata"], dict):
                raise ValueError()
            selected = row["selection"]
            if not isinstance(selected, dict) or set(selected) != {"choice", "revision"}:
                raise ValueError()
            if selected["choice"] is not None:
                if not isinstance(selected["choice"], dict) or set(selected["choice"]) != {
                    "owner",
                    "grant",
                }:
                    raise ValueError()
                identifier(selected["choice"]["owner"])
            selection(row)
            shares = row["shares"]
            if not isinstance(shares, dict) or len(shares) > MAX_SHARES:
                raise ValueError()
            for recipient, offered in shares.items():
                identifier(recipient)
                if recipient == data["person"] or set(offered) != {
                    "revision",
                    "policy",
                    "capabilities",
                }:
                    raise ValueError()
                if not isinstance(offered["capabilities"], list) or len(
                    offered["capabilities"]
                ) != len(set(offered["capabilities"])):
                    raise ValueError()
                policy = Policy(offered["policy"], frozenset(offered["capabilities"]))
                rules.Grant(offered["revision"], policy.capabilities)
            control = row["control"]
            if not isinstance(control, dict) or set(control) != {
                "revision",
                "epoch",
                "state",
                "generation",
                "human_until",
                "attempt",
            }:
                raise ValueError()
            for field in ("revision", "epoch"):
                if not isinstance(control[field], str) or not 0 < len(control[field]) <= 128:
                    raise ValueError()
            if control["state"] not in {"active", "disconnected", "disconnecting", "reconnecting"}:
                raise ValueError()
            if type(control["generation"]) is not int or control["generation"] < 0:
                raise ValueError()
            if type(control["human_until"]) not in (int, float) or not math.isfinite(
                control["human_until"]
            ):
                raise ValueError()
            attempt = control["attempt"]
            if attempt is not None:
                if not isinstance(attempt, dict) or set(attempt) != {
                    "revision",
                    "staged",
                    "expires",
                }:
                    raise ValueError()
                if (
                    attempt["revision"] != control["revision"]
                    or type(attempt["staged"]) is not bool
                ):
                    raise ValueError()
                if type(attempt["expires"]) not in (int, float) or not math.isfinite(
                    attempt["expires"]
                ):
                    raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        raise StateError() from None


class People:
    """Application membership is checked by the host before every entry point.

    Only verified immutable identities are accepted. Passing an identity to
    enroll/bind is an explicit identity action, not a name/header interpretation.
    """

    def __init__(
        self,
        root: Path | Store,
        *,
        clock: Callable[[], float] = time.time,
        max_shares: int = MAX_SHARES,
        directory: Directory | None = None,
    ):
        if type(max_shares) is not int or not 1 <= max_shares <= MAX_SHARES:
            raise ValueError("bounded sharing limit required")
        self.store = root if isinstance(root, Store) else Store(root)
        self.clock = clock
        self.max_shares = max_shares
        self.directory = directory

    def read(self, person: str) -> dict[str, Any]:
        data = self.store.read(person)
        validate(data)
        return data

    def namespace(self, person: str, namespace: str) -> dict[str, Any]:
        identifier(namespace)
        try:
            return cast(dict[str, Any], self.read(person)["namespaces"][namespace])
        except KeyError:
            raise StateError() from None

    def _inactive(self, person: str) -> dict[str, Any] | None:
        path = self.store.root / ".inactive" / (identifier(person) + ".json")
        if not path.parent.exists() and not path.parent.is_symlink():
            return None
        private_directory(path.parent)
        try:
            value = read_json(path)
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError):
            raise StateError() from None
        if (
            not isinstance(value, dict)
            or set(value) != {"version", "kind", "identity"}
            or type(value["version"]) is not int
            or value["version"] != 1
            or value["kind"] not in ("inactive", "forgotten")
        ):
            raise StateError()
        binding = value["identity"]
        if binding is not None:
            if not isinstance(binding, dict) or set(binding) != {"issuer", "sub"}:
                raise StateError()
            try:
                Identity(binding["issuer"], binding["sub"])
            except ValueError:
                raise StateError() from None
        return cast(dict[str, Any], value)

    def require_admitted(self, person: str) -> None:
        """Check durable local admission, with no directory/network work under locks."""
        if self._inactive(person) is not None:
            raise StateError("person_inactive")
        self.read(person)

    def set_inactive(self, person: str, identity: Identity | None = None) -> None:
        """Record a verified missing-group sign-in; None is an operator-only action."""
        identifier(person)
        with self.store.lock():
            existing = self._inactive(person)
            if identity is not None:
                if self.store.exists(person):
                    binding = self.read(person)["identity"]
                    if binding not in (None, identity.record()):
                        raise StateError("identity_mismatch")
                if existing and existing["identity"] not in (None, identity.record()):
                    raise StateError("identity_mismatch")
            if existing and existing["kind"] == "forgotten":
                return
            root = self.store.root / ".inactive"
            private_directory(root)
            atomic_json(
                root / (person + ".json"),
                {
                    "version": 1,
                    "kind": "inactive",
                    "identity": identity.record()
                    if identity
                    else existing["identity"]
                    if existing
                    else None,
                },
            )

    def _directory_lookup(self, identity: Identity) -> DirectoryPerson:
        if self.directory is None:
            return DirectoryPerson(True)
        if getattr(self.store._local, "locked", False):
            raise RuntimeError("directory lookup requires leaving the authority transaction")
        try:
            verdict = self.directory(identity)
        except Exception:
            raise StateError("directory_unavailable") from None
        if verdict is None:
            return DirectoryPerson(False)
        if not isinstance(verdict, DirectoryPerson):
            raise StateError("directory_unavailable")
        return verdict

    def refresh(self, person: str) -> None:
        """Refresh a pinned exact subject outside transactions, before admission.

        A positive directory answer never reactivates a previously inactive
        person. Re-admission still needs their verified signed browser identity.
        """
        if self.directory is None:
            return
        original = self.read(person)["identity"]
        if original is None:
            raise StateError("directory_identity_required")
        identity = Identity(original["issuer"], original["sub"])
        verdict = self._directory_lookup(identity)
        with self.store.lock():
            data = self.read(person)
            if data["identity"] != original:
                raise StateError("identity_mismatch")
            if not verdict.admitted:
                self.set_inactive(person, identity)
                raise StateError("person_inactive")
            if verdict.label is not None:
                data["name"] = _label(verdict.label)
                self.store.write(person, data)

    def contact(
        self,
        person: str,
        *,
        namespaces: Iterable[str],
        identity: Identity | None = None,
        label: str | None = None,
        admitted: bool = True,
        explicit: bool = False,
        readmit: bool = False,
        retained_credentials: bool = False,
    ) -> dict[str, Any]:
        """Enroll trusted first contact without a host people list or implicit selection.

        Ordinary browser/MCP contact cannot clear departed status. Readmission
        is only for a newly verified successful identity-provider callback.
        The host passes identity only for a verified signed browser identity and
        admitted only after current group/admission checks.
        """
        identifier(person)
        if (
            type(admitted) is not bool
            or type(explicit) is not bool
            or type(readmit) is not bool
            or (explicit or readmit)
            and identity is None
        ):
            raise ValueError("verified admission and explicit identity action required")
        if not admitted:
            self.set_inactive(person, identity)
            raise StateError("person_inactive")
        if identity is not None:
            verdict = self._directory_lookup(identity)
            if not verdict.admitted:
                self.set_inactive(person, identity)
                raise StateError("person_inactive")
            if verdict.label is not None:
                label = verdict.label
        elif self.directory is not None:
            # An existing pinned identity can be checked, but an unknown header
            # cannot turn an exact-subject directory into a person-ID lookup.
            self.refresh(person)
        clean = _label(label)
        with self.store.lock():
            inactive = self._inactive(person)
            if inactive:
                if identity is not None and inactive["identity"] not in (None, identity.record()):
                    raise StateError("identity_mismatch")
                if inactive["kind"] == "forgotten" or identity is None or not readmit:
                    raise StateError("person_inactive")
            data = self.enroll(
                person, namespaces=namespaces, retained_credentials=retained_credentials
            )
            if identity is not None:
                if data["identity"] not in (None, identity.record()):
                    raise StateError("identity_mismatch")
                if explicit:
                    self._bind(data, identity)
            if identity is not None or label is not None:
                data["name"] = clean
            self.store.write(person, data)
            if inactive:
                (self.store.root / ".inactive" / (person + ".json")).unlink()
                # Persist the re-admission as carefully as the denied marker.
                fd = os.open(
                    self.store.root / ".inactive", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            return data

    def roster(self) -> list[Person]:
        """Enrolled people plus retained grant recipients; names never grant access."""
        with self.store.lock():
            records: dict[str, dict[str, Any] | None] = {}
            for person in self.store.people():
                try:
                    records[person] = self.read(person)
                except StateError:
                    records[person] = None
            for data in list(records.values()):
                if data is not None:
                    for row in data["namespaces"].values():
                        for recipient in row["shares"]:
                            records.setdefault(recipient, None)
            labels = {
                person: str(data["name"] or person) if data else person
                for person, data in records.items()
            }

            def counts_of(values: dict[str, str]) -> dict[str, int]:
                counts: dict[str, int] = {}
                for label in values.values():
                    key = label.casefold()
                    counts[key] = counts.get(key, 0) + 1
                return counts

            counts = counts_of(labels)
            labels = {
                person: label + f" ({person})" if counts[label.casefold()] > 1 else label
                for person, label in labels.items()
            }
            # Real names can imitate generated suffixes, and distinct IDs can
            # casefold alike. Reserve unique names, then allocate finite suffixes.
            counts = counts_of(labels)
            used = {label.casefold() for label in labels.values() if counts[label.casefold()] == 1}
            for person in sorted(labels):
                label = labels[person]
                if counts[label.casefold()] == 1:
                    continue
                base = label + f" ({person})"
                candidate, suffix = base, 0
                while candidate.casefold() in used:
                    suffix += 1
                    candidate = base + f" [{suffix}]"
                labels[person] = candidate
                used.add(candidate.casefold())
            found = []
            for person in sorted(records):
                available = records[person] is not None
                try:
                    active = available and self._inactive(person) is None
                except StateError:
                    active = False
                label = labels[person]
                found.append(Person(person, label, active, available))
            return found

    def label(self, person: str) -> str:
        identifier(person)
        return next((row.label for row in self.roster() if row.id == person), person)

    def forget(self, person: str) -> tuple[str, ...]:
        """Operator departure: deny first, then revoke references without repairing damage.

        Native credential disposal stays with the application. The retained
        forgotten marker cannot be cleared by contact or ordinary membership.
        """
        identifier(person)
        unavailable = []
        with self.store.lock():
            root = self.store.root / ".inactive"
            private_directory(root)
            try:
                identity = self.read(person)["identity"]
            except StateError:
                identity = None
            atomic_json(
                root / (person + ".json"),
                {
                    "version": 1,
                    "kind": "forgotten",
                    "identity": identity,
                },
            )
            for owner in self.store.people():
                try:
                    data = self.read(owner)
                except StateError:
                    unavailable.append(owner)
                    continue
                changed = False
                for row in data["namespaces"].values():
                    if owner == person:
                        row["shares"] = {}
                        row["selection"] = {"choice": None, "revision": rules.revision()}
                        row["control"].update(
                            revision=rules.revision(),
                            epoch=rules.revision(),
                            state="disconnected",
                            human_until=0,
                            attempt=None,
                        )
                        changed = True
                    else:
                        if person in row["shares"]:
                            del row["shares"][person]
                            changed = True
                        chosen = row["selection"]["choice"]
                        if chosen and chosen["owner"] == person:
                            row["selection"] = {"choice": None, "revision": rules.revision()}
                            changed = True
                if changed:
                    self.store.write(owner, data)
        return tuple(unavailable)

    def enroll(
        self,
        person: str,
        *,
        namespaces: Iterable[str],
        identity: Identity | None = None,
        retained_credentials: bool = False,
    ) -> dict[str, Any]:
        identifier(person)
        requested = set(namespaces)
        for namespace in requested:
            identifier(namespace)
        with self.store.lock():
            if self.store.exists(person):
                data = self.read(person)
                if not requested <= set(data["namespaces"]):
                    raise StateError("namespace_migration_required")
                if identity is not None:
                    self._bind(data, identity)
                    self.store.write(person, data)
                return data
            if retained_credentials or len(self.store.people()) >= MAX_PEOPLE:
                raise StateError()
            data = {
                "version": 3,
                "person": person,
                "identity": identity.record() if identity else None,
                "name": None,
                "namespaces": {namespace: initial_namespace() for namespace in sorted(requested)},
            }
            validate(data)
            self.store.write(person, data)
            return data

    @staticmethod
    def _bind(data: dict[str, Any], identity: Identity) -> None:
        if data["identity"] not in (None, identity.record()):
            raise StateError("identity_mismatch")
        data["identity"] = identity.record()

    def bind(self, person: str, identity: Identity, *, name: str | None = None) -> None:
        with self.store.lock():
            self.require_admitted(person)
            data = self.read(person)
            self._bind(data, identity)
            if name is not None:
                if not isinstance(name, str) or len(name) > 80:
                    raise ValueError("bounded display name required")
                data["name"] = name
            self.store.write(person, data)

    def offer(
        self,
        owner: str,
        namespace: str,
        recipient: str,
        *,
        policy: Policy,
        capabilities: frozenset[str],
        expected: str | None,
    ) -> rules.Grant:
        if owner == recipient or not capabilities <= policy.capabilities:
            raise ValueError("invalid offer")
        with self.store.lock():
            self.require_admitted(owner)
            self.require_admitted(recipient)
            self.namespace(recipient, namespace)
            data = self.read(owner)
            row = self.namespace(owner, namespace)
            previous = row["shares"].get(recipient)
            # A policy update always creates a fresh grant; it cannot revive a choice.
            old = (
                rules.Grant(previous["revision"], frozenset(previous["capabilities"]))
                if previous
                else None
            )
            offered = rules.offer(old, expected=expected, capabilities=capabilities)
            if previous and previous["policy"] != policy.version:
                offered = rules.Grant(rules.revision(), capabilities)
            if recipient not in row["shares"] and len(row["shares"]) >= self.max_shares:
                raise StateError("share_limit")
            row["shares"][recipient] = {
                "revision": offered.revision,
                "capabilities": sorted(offered.capabilities),
                "policy": policy.version,
            }
            data["namespaces"][namespace] = row
            self.store.write(owner, data)
            return offered

    def selected(
        self,
        actor: str,
        namespace: str,
        *,
        policy: Policy,
        capability: str | None = None,
    ) -> tuple[rules.Selection, rules.Grant | None]:
        self.require_admitted(actor)
        row = self.namespace(actor, namespace)
        selected = selection(row)
        offered = None
        if selected.choice and selected.choice.owner != actor:
            self.require_admitted(selected.choice.owner)
            owner_row = self.namespace(selected.choice.owner, namespace)
            offered = grant(owner_row["shares"].get(actor), policy)
        if capability is not None and capability not in policy.capabilities:
            raise ValueError("undeclared capability")
        rules.resolve(actor, selected, offered, capability=capability)
        return selected, offered

    def select(
        self,
        actor: str,
        namespace: str,
        owner: str,
        *,
        policy: Policy,
        expected: str,
        grant_revision: str | None = None,
    ) -> rules.Selection:
        with self.store.lock():
            self.require_admitted(actor)
            self.require_admitted(owner)
            data = self.read(actor)
            row = self.namespace(actor, namespace)
            owner_row = self.namespace(owner, namespace)
            offered = grant(owner_row["shares"].get(actor), policy) if owner != actor else None
            selected = rules.choose(
                actor,
                selection(row),
                rules.Choice(owner, grant_revision),
                offered,
                expected=expected,
            )
            save_selection(row, selected)
            data["namespaces"][namespace] = row
            self.store.write(actor, data)
            return selected

    def revoke(
        self,
        owner: str,
        namespace: str,
        recipient: str,
        *,
        expected: str,
        leaving: bool = False,
    ) -> None:
        with self.store.lock():
            data = self.read(owner)
            row = self.namespace(owner, namespace)
            previous = row["shares"].get(recipient)
            offered = (
                rules.Grant(previous["revision"], frozenset(previous["capabilities"]))
                if previous
                else None
            )
            rules.revoke(offered, expected=expected)
            del row["shares"][recipient]
            data["namespaces"][namespace] = row
            self.store.write(owner, data)  # Revocation commits before selection cleanup.
            if leaving:
                recipient_data = self.read(recipient)
                recipient_row = self.namespace(recipient, namespace)
                save_selection(recipient_row, rules.leave(selection(recipient_row), owner))
                recipient_data["namespaces"][namespace] = recipient_row
                self.store.write(recipient, recipient_data)

    def leave(self, actor: str, namespace: str, owner: str, *, expected: str) -> None:
        self.revoke(owner, namespace, actor, expected=expected, leaving=True)

    def offers(
        self, actor: str, namespace: str, *, policy: Policy
    ) -> tuple[list[dict[str, Any]], bool]:
        found: list[dict[str, Any]] = []
        unavailable = False
        with self.store.lock():
            self.require_admitted(actor)
            self.namespace(actor, namespace)
            for owner in self.store.people():
                if owner == actor:
                    continue
                try:
                    self.require_admitted(owner)
                    row = self.namespace(owner, namespace)
                except StateError:
                    unavailable = True
                    continue
                offered = grant(row["shares"].get(actor), policy)
                if offered:
                    found.append({"owner": owner, "grant": offered})
        return found, unavailable
