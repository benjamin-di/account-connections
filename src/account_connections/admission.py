"""Immutable call routing and account-context tokens, checked before I/O or caches."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from .controls import Controls
from .people import People, Policy
from .storage import StateError, identifier


class HeaderValues(Protocol):
    def getlist(self, key: str) -> list[str]: ...


def gateway_person(
    headers: HeaderValues | Mapping[str, str],
    *,
    backend_authenticated: bool,
    header: str = "x-fleet-person",
) -> str:
    """Read one gateway-set person only after the host verifies its backend bearer.

    The gateway must overwrite the caller's header from its verified human or
    workload identity. This reader does not verify JWTs or trust a tool argument.
    Preserve repeated headers when adapting a framework request.
    """
    if backend_authenticated is not True or not isinstance(header, str) or not header:
        raise StateError("account_selection_needed")
    if isinstance(headers, Mapping):
        # Framework multidicts must use getlist, before Mapping collapses values.
        getlist = getattr(headers, "getlist", None)
        values = (
            getlist(header)
            if callable(getlist)
            else [value for key, value in headers.items() if key.lower() == header.lower()]
        )
    else:
        values = headers.getlist(header)
    if len(values) != 1:
        raise StateError("account_selection_needed")
    try:
        return identifier(values[0])
    except ValueError:
        raise StateError("account_selection_needed") from None


@dataclass(frozen=True)
class Admission:
    actor: str
    owner: str
    namespace: str
    selection_revision: str
    grant_revision: str | None
    policy_version: str
    capabilities: frozenset[str]
    epoch: str
    control_revision: str

    @property
    def shared(self) -> bool:
        return self.actor != self.owner


class AdmissionService:
    def __init__(self, people: People, controls: Controls, key: bytes):
        if people.store is not controls.store:
            raise ValueError("one authority store required")
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("a private key of at least 32 bytes is required")
        self.people, self.controls, self._key = people, controls, key

    def capture(
        self,
        actor: str,
        namespace: str,
        *,
        policy: Policy,
        capability: str | None = None,
        context: str | None = None,
        require_context: bool = False,
        shared_context_only: bool = True,
    ) -> Admission:
        self.people.refresh(actor)
        selected = self.people.namespace(actor, namespace)["selection"]["choice"]
        if selected and selected["owner"] != actor:
            self.people.refresh(selected["owner"])
        with self.people.store.lock():
            self.people.require_admitted(actor)
            if self.people.namespace(actor, namespace)["selection"]["choice"] != selected:
                raise StateError("account_changed")
            selected, offered = self.people.selected(
                actor,
                namespace,
                policy=policy,
                capability=capability,
            )
            assert selected.choice is not None
            owner = selected.choice.owner
            control = self.controls.require_active(owner, namespace)
            captured = Admission(
                actor,
                owner,
                namespace,
                selected.revision,
                offered.revision if offered else None,
                policy.version,
                offered.capabilities if offered else policy.capabilities,
                control["epoch"],
                control["revision"],
            )
            if (
                require_context
                and (captured.shared or not shared_context_only)
                and not self.matches(context, captured)
            ):
                raise StateError("account_changed")
            return captured

    def token(self, admitted: Admission) -> str:
        raw = json.dumps(
            [
                "account-context-v1",
                admitted.actor,
                admitted.owner,
                admitted.namespace,
                admitted.selection_revision,
                admitted.grant_revision,
                admitted.policy_version,
                sorted(admitted.capabilities),
                admitted.epoch,
                admitted.control_revision,
            ],
            separators=(",", ":"),
        ).encode()
        return hmac.new(self._key, raw, hashlib.sha256).hexdigest()

    def matches(self, token: str | None, admitted: Admission) -> bool:
        return bool(
            isinstance(token, str)
            and len(token) == 64
            and all(character in "0123456789abcdef" for character in token)
            and hmac.compare_digest(token, self.token(admitted))
        )

    def revalidate(self, admitted: Admission, *, policy: Policy) -> Admission:
        current = self.capture(admitted.actor, admitted.namespace, policy=policy)
        if current != admitted:
            raise StateError("account_changed")
        return current
