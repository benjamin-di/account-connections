"""Pure transitions. Call under the host's authority lock and persist before returning.

An owner reference identifies a retained connection slot in the application's
provider namespace. It never identifies a session or grants API access.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Literal

Outcome = Literal[
    "account_selection_needed", "account_changed", "shared_access_removed", "capability_not_shared"
]


class ConnectionError(Exception):
    """Closed public outcome; adapters translate it into their error vocabulary."""

    def __init__(self, code: Outcome):
        self.code = code
        super().__init__(code)


def revision() -> str:
    """New, never deliberately reused revision, including A → B → A changes."""
    return secrets.token_hex(16)


def _identifier(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("nonempty bounded identifier required")


@dataclass(frozen=True)
class Grant:
    revision: str
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        _identifier(self.revision)
        if not isinstance(self.capabilities, frozenset):
            raise ValueError("immutable capabilities required")
        for capability in self.capabilities:
            _identifier(capability)


@dataclass(frozen=True)
class Choice:
    owner: str
    grant_revision: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.owner)
        if self.grant_revision is not None:
            _identifier(self.grant_revision)


@dataclass(frozen=True)
class Selection:
    choice: Choice | None
    revision: str

    def __post_init__(self) -> None:
        _identifier(self.revision)
        if self.choice is not None and not isinstance(self.choice, Choice):
            raise ValueError("choice required")


def offer(previous: Grant | None, *, expected: str | None, capabilities: frozenset[str]) -> Grant:
    """Create/update an offer without changing any recipient selection."""
    if (previous.revision if previous else None) != expected:
        raise ConnectionError("account_changed")
    candidate = Grant(revision(), capabilities)
    return previous if previous and previous.capabilities == capabilities else candidate


def revoke(current: Grant | None, *, expected: str) -> None:
    """Validate revocation before the adapter durably removes the grant."""
    if current is None or current.revision != expected:
        raise ConnectionError("shared_access_removed")


def resolve(
    actor: str, selected: Selection, grant: Grant | None, *, capability: str | None = None
) -> Choice:
    """Authorize before caches/I/O. The host supplies the selected owner's current
    grant to this actor in this provider namespace. Native barriers still apply.
    """
    _identifier(actor)
    choice = selected.choice
    if choice is None:
        raise ConnectionError("account_selection_needed")
    if choice.owner == actor:
        if choice.grant_revision is not None:
            raise ConnectionError("account_selection_needed")
    else:
        if grant is None or grant.revision != choice.grant_revision:
            raise ConnectionError("shared_access_removed")
        if capability is not None and capability not in grant.capabilities:
            raise ConnectionError("capability_not_shared")
    return choice


def choose(
    actor: str, selected: Selection, choice: Choice, grant: Grant | None, *, expected: str
) -> Selection:
    """Explicit acceptance and selection in one stale-action-protected transition."""
    if selected.revision != expected:
        raise ConnectionError("account_changed")
    resolve(actor, Selection(choice, selected.revision), grant)
    return selected if selected.choice == choice else Selection(choice, revision())


def leave(selected: Selection, owner: str) -> Selection:
    """After durable revocation, clear this owner even after a scope change.

    Keep the transaction lock from revocation through this write. A concurrent
    selection of another owner is preserved. Crash after revoke remains denied.
    """
    if selected.choice is not None and selected.choice.owner == owner:
        return Selection(None, revision())
    return selected
