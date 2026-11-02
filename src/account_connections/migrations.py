"""Explicit one-way native-record adapters. Never migrate credential bytes.

Quiesce old readers/writers and hold their native authority lock before calling.
The library additionally serializes the destination. Native credential paths,
budgets, profiles and caches stay in place; applications change their routing.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Mapping
from typing import Any, cast

from .people import Identity, People, Policy, initial_namespace, validate
from .storage import StateError, atomic_json, directory, identifier, read_json


def _record(person: str, identity: Identity | None = None) -> dict[str, Any]:
    return {
        "version": 3,
        "person": identifier(person),
        "identity": identity.record() if identity else None,
        "name": None,
        "namespaces": {},
    }


def _phase(native: Mapping[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(native, dict)
        or not set(native) <= {"phase", "revision", "human_until"}
        or type(native.get("phase")) is not int
        or native["phase"] not in range(4)
        or not isinstance(native.get("revision"), str)
        or not native["revision"]
        or len(native["revision"]) > 128
    ):
        raise StateError("migration_source_invalid")
    control = initial_namespace()["control"]
    control.update(
        revision=native["revision"],
        epoch=native["revision"],
        state=("active", "disconnected", "disconnecting", "reconnecting")[native["phase"]],
        human_until=native.get("human_until", 0),
    )
    # In-flight native windows must be restarted: pending credential payloads are
    # never imported, and their old callbacks have no canonical staged attempt.
    return cast(dict[str, Any], control)


def install(
    people: People,
    person: str,
    converted: dict[str, Any],
    *,
    source: dict[str, Any],
    kind: str,
) -> dict[str, Any]:
    """Snapshot → stopped receipt → record → complete receipt, resumably.

    A completed receipt is never used to repair a lost canonical record. During
    an interrupted migration runtime reads are blocked, including after record
    publication and before the final receipt. Resume requires the exact source.
    """
    validate(converted)
    if converted["person"] != person:
        raise ValueError("migration person mismatch")
    identifier(kind)
    raw = json.dumps(source, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    digest = hashlib.sha256(raw).hexdigest()
    with people.store.lock():
        migrations = people.store.root / ".migrations"
        snapshots = people.store.root / ".snapshots"
        directory(migrations)
        directory(snapshots)
        receipt_path, snapshot = migrations / (person + ".json"), snapshots / (person + ".json")
        if os.path.lexists(receipt_path):
            receipt = read_json(receipt_path)
            if (
                not isinstance(receipt, dict)
                or receipt.get("source") != digest
                or receipt.get("kind") != kind
            ):
                raise StateError("migration_source_changed")
            if receipt.get("state") == "complete":
                return people.read(person)
            if receipt.get("state") != "pending":
                raise StateError()
        else:
            if os.path.lexists(people.store.path(person)) or os.path.lexists(
                people.store.marker(person)
            ):
                raise StateError("migration_destination_exists")
            if os.path.lexists(snapshot):
                if read_json(snapshot) != source:
                    raise StateError("migration_source_changed")
            else:
                atomic_json(snapshot, source)
            atomic_json(receipt_path, {"kind": kind, "source": digest, "state": "pending"})
        if read_json(snapshot) != source:
            raise StateError("migration_source_changed")
        people.store.write(person, converted)
        atomic_json(receipt_path, {"kind": kind, "source": digest, "state": "complete"})
        return people.read(person)


def hktvmall(
    people: People,
    person: str,
    native: dict[str, Any],
    *,
    policy: Policy,
    namespace: str = "default",
    shopping: str = "shopping",
    history: str = "history",
) -> dict[str, Any]:
    """Map native v1/v2 people controls without changing revision references."""
    if not {shopping, history} <= policy.capabilities:
        raise ValueError("declare native capabilities")
    required = {"version", "epoch", "state", "owner", "provider_email", "generation"}
    allowed = required | {"shared_with", "name", "shares", "selection", "selection_revision"}
    if (
        not required <= set(native) <= allowed
        or type(native["version"]) is not int
        or native["version"] not in (1, 2)
        or native["state"] not in ("active", "disconnecting", "disconnected")
    ):
        raise StateError("migration_source_invalid")
    identity = native["owner"]
    if identity is not None and (
        not isinstance(identity, dict) or set(identity) != {"issuer", "sub"}
    ):
        raise StateError("migration_source_invalid")
    data = _record(person, Identity(identity["issuer"], identity["sub"]) if identity else None)
    data["name"] = native.get("name")
    row = initial_namespace()
    row["control"].update(
        revision=native["epoch"],
        epoch=native["epoch"],
        state=native["state"],
        generation=native["generation"],
    )
    row["metadata"] = {"provider_email": native["provider_email"]}
    if native["version"] == 2:
        if not {"shares", "selection", "selection_revision", "shared_with"} <= set(native):
            raise StateError("migration_source_invalid")
        if set(native["shares"]) != set(native["shared_with"]):
            raise StateError("migration_source_invalid")
        for member, offered in native["shares"].items():
            if (
                set(offered) != {"revision", "order_history"}
                or type(offered["order_history"]) is not bool
            ):
                raise StateError("migration_source_invalid")
            row["shares"][member] = {
                "revision": offered["revision"],
                "policy": policy.version,
                "capabilities": sorted(
                    {shopping, *([history] if offered["order_history"] else [])}
                ),
            }
        chosen = native["selection"]
        if chosen is not None and (
            not isinstance(chosen, dict) or set(chosen) != {"account", "grant"}
        ):
            raise StateError("migration_source_invalid")
        row["selection"] = {
            "choice": {"owner": chosen["account"], "grant": chosen["grant"]} if chosen else None,
            "revision": native["selection_revision"],
        }
    else:
        if native.get("shared_with"):
            raise StateError("migration_source_invalid")
        row["selection"]["choice"] = {"owner": person, "grant": None}
    data["namespaces"][identifier(namespace)] = row
    return install(people, person, data, source=native, kind="hktvmall-v2")


def amazon(
    people: People,
    owner: str,
    native_controls: dict[str, Any],
    *,
    identity: Identity | None = None,
    metadata: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Publish retained provider paths with the authority, before completion.

    Optional routing metadata contains paths and a marketplace preference only;
    credentials never enter the snapshot. A retry must supply the exact mapping.
    """
    data = _record(owner, identity)
    if not native_controls:
        raise StateError("migration_source_invalid")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or set(metadata) != set(native_controls)
        or any(
            not isinstance(row, dict)
            or set(row) != {"jar_path", "keeper_path", "default_site"}
            or any(
                not isinstance(value, str) or not value or len(value) > 4096
                for value in row.values()
            )
            for row in metadata.values()
        )
    ):
        raise StateError("migration_source_invalid")
    for namespace, native in native_controls.items():
        identifier(namespace)
        if not isinstance(native, dict) or not set(native) <= {"revision", "phase", "human_until"}:
            raise StateError("migration_source_invalid")
        row = initial_namespace()
        row["control"] = _phase(native)
        row["selection"]["choice"] = {"owner": owner, "grant": None}
        if metadata is not None:
            row["metadata"] = copy.deepcopy(metadata[namespace])
        data["namespaces"][namespace] = row
    source = {"controls": native_controls, "identity": identity.record() if identity else None}
    if metadata is not None:
        source["metadata"] = copy.deepcopy(metadata)
    return install(people, owner, data, source=source, kind="amazon-v1")


def newsclip(
    people: People,
    person: str,
    native_access: dict[str, Any],
    native_controls: dict[str, Any],
    *,
    policy: Policy,
    identity: Identity | None = None,
    subscription: str = "subscription",
) -> dict[str, Any]:
    """Map native subscription access and account-scoped publisher controls."""
    if subscription not in policy.capabilities:
        raise ValueError("declare subscription capability")
    if (
        set(native_access) != {"version", "providers"}
        or type(native_access["version"]) is not int
        or native_access["version"] != 1
        or not isinstance(native_access["providers"], dict)
        or set(native_access["providers"]) != set(native_controls)
    ):
        raise StateError("migration_source_invalid")
    data = _record(person, identity)
    for namespace, native in native_access["providers"].items():
        identifier(namespace)
        if not isinstance(native, dict) or set(native) != {"selection", "revision", "grants"}:
            raise StateError("migration_source_invalid")
        row = initial_namespace()
        row["control"] = _phase(native_controls[namespace])
        chosen = native["selection"]
        if chosen is not None and (
            not isinstance(chosen, dict) or set(chosen) != {"owner", "grant"}
        ):
            raise StateError("migration_source_invalid")
        row["selection"] = {"choice": copy.deepcopy(chosen), "revision": native["revision"]}
        row["shares"] = {
            recipient: {
                "revision": offered,
                "policy": policy.version,
                "capabilities": [subscription],
            }
            for recipient, offered in native["grants"].items()
        }
        data["namespaces"][namespace] = row
    source = {
        "access": native_access,
        "controls": native_controls,
        "identity": identity.record() if identity else None,
    }
    return install(people, person, data, source=source, kind="newsclip-v1")
