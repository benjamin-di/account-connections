"""Reusable offline conformance checks for application-provided connection setups.

Subclass ``ConnectionConformance`` in pytest and supply ``connection_factory``
(a fixture returning ``Callable[[Path], Harness]``). The factory must use the
application's actual store/configuration, never an unrelated in-memory facade.
Provider/session behavior still needs the application's characterization tests.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .admission import AdmissionService
from .controls import Controls
from .people import Identity, People, Policy
from .rules import ConnectionError
from .storage import StateError


@dataclass(frozen=True)
class Harness:
    people: People
    controls: Controls
    admission: AdmissionService
    policy: Policy
    namespace: str
    restart: Callable[[], Harness]

    def connect(self, owner: str) -> None:
        self.people.enroll(owner, namespaces=[self.namespace])
        attempt = self.controls.begin(owner, self.namespace)
        self.controls.stage(owner, self.namespace, attempt, lambda: None)
        self.controls.publish(owner, self.namespace, attempt, lambda: None)
        row = self.people.namespace(owner, self.namespace)
        self.people.select(
            owner,
            self.namespace,
            owner,
            policy=self.policy,
            expected=row["selection"]["revision"],
        )

    def share(self, owner: str = "alice", recipient: str = "bob") -> str:
        self.people.enroll(recipient, namespaces=[self.namespace])
        offered = self.people.offer(
            owner,
            self.namespace,
            recipient,
            policy=self.policy,
            capabilities=self.policy.capabilities,
            expected=None,
        )
        row = self.people.namespace(recipient, self.namespace)
        self.people.select(
            recipient,
            self.namespace,
            owner,
            policy=self.policy,
            expected=row["selection"]["revision"],
            grant_revision=offered.revision,
        )
        return offered.revision


@contextmanager
def refused(code: str | None = None) -> Iterator[None]:
    try:
        yield
    except (StateError, ConnectionError) as error:
        if code is not None:
            assert error.code == code
    else:
        raise AssertionError("operation unexpectedly retained authority")


Factory = Callable[[Path], Harness]


class ConnectionConformance:
    def test_first_contact_never_selects_or_pins_implicitly(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        identity = Identity("https://identity.example.com", "subject-alice")
        h.people.contact("alice", namespaces=[h.namespace], identity=identity, label="Alice")
        row = h.people.read("alice")
        assert row["identity"] is None and row["name"] == "Alice"
        assert row["namespaces"][h.namespace]["selection"]["choice"] is None
        with refused("account_selection_needed"):
            h.admission.capture("alice", h.namespace, policy=h.policy)
        h.people.contact("alice", namespaces=[h.namespace], identity=identity, explicit=True)
        assert h.restart().people.read("alice")["identity"] == identity.record()

    def test_roster_labels_fall_back_and_disambiguate(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.people.contact("alice", namespaces=[h.namespace], label="Reader")
        h.people.contact("bob", namespaces=[h.namespace], label="reader")
        h.people.contact("charlie", namespaces=[h.namespace])
        rows = {row.id: row for row in h.restart().people.roster()}
        assert rows["alice"].label == "Reader (alice)"
        assert rows["bob"].label == "reader (bob)"
        assert rows["charlie"].label == "charlie"
        assert all(row.active and row.available for row in rows.values())

    def test_removed_group_is_refused_after_restart_and_header_contact(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.share()
        identity = Identity("https://identity.example.com", "subject-bob")
        h.people.bind("bob", identity)
        with refused("person_inactive"):
            h.people.contact("bob", namespaces=[h.namespace], identity=identity, admitted=False)
        restarted = h.restart()
        with refused("person_inactive"):
            restarted.people.contact("bob", namespaces=[h.namespace])
        with refused("person_inactive"):
            restarted.people.contact("bob", namespaces=[h.namespace], identity=identity)
        with refused("person_inactive"):
            restarted.admission.capture("bob", h.namespace, policy=h.policy)

    def test_stale_revision_never_publishes(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        old = h.controls.begin("alice", h.namespace)
        h.controls.begin("alice", h.namespace)
        called: list[bool] = []
        with refused("account_changed"):
            h.controls.publish("alice", h.namespace, old, lambda: called.append(True))
        assert not called

    def test_disconnect_survives_restart(self, connection_factory: Factory, tmp_path: Path) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.controls.disconnect("alice", h.namespace, lambda: None)
        with refused("owner_reconnect"):
            h.restart().admission.capture("alice", h.namespace, policy=h.policy)

    def test_revoke_never_falls_back(self, connection_factory: Factory, tmp_path: Path) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.connect("bob")
        offered = h.share()
        h.people.revoke("alice", h.namespace, "bob", expected=offered)
        with refused("shared_access_removed"):
            h.admission.capture("bob", h.namespace, policy=h.policy)

    def test_leave_never_falls_back(self, connection_factory: Factory, tmp_path: Path) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.connect("bob")
        offered = h.share()
        h.people.leave("bob", h.namespace, "alice", expected=offered)
        with refused("account_selection_needed"):
            h.admission.capture("bob", h.namespace, policy=h.policy)

    def test_missing_record_is_never_recreated(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.people.store.path("alice").unlink()
        with refused():
            h.restart().people.enroll("alice", namespaces=[h.namespace])

    def test_retained_credentials_prevent_enrollment(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        with refused():
            h.people.enroll("alice", namespaces=[h.namespace], retained_credentials=True)

    def test_captured_work_keeps_its_owner(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        offered = h.share()
        admitted = h.admission.capture("bob", h.namespace, policy=h.policy)
        h.people.revoke("alice", h.namespace, "bob", expected=offered)
        assert admitted.owner == "alice" and admitted.actor == "bob"
        with h.controls.admitted(admitted.owner, h.namespace, epoch=admitted.epoch):
            assert admitted.owner == "alice"
        with refused("shared_access_removed"):
            h.admission.capture("bob", h.namespace, policy=h.policy)

    def test_selection_change_invalidates_token(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.connect("bob")
        h.share()
        old = h.admission.capture("bob", h.namespace, policy=h.policy)
        row = h.people.namespace("bob", h.namespace)
        h.people.select(
            "bob", h.namespace, "bob", policy=h.policy, expected=row["selection"]["revision"]
        )
        with refused("account_changed"):
            h.admission.capture(
                "bob",
                h.namespace,
                policy=h.policy,
                context=h.admission.token(old),
                require_context=True,
                shared_context_only=False,
            )

    def test_reissued_grant_never_revives_selection(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        old = h.share()
        h.people.revoke("alice", h.namespace, "bob", expected=old)
        new = h.people.offer(
            "alice",
            h.namespace,
            "bob",
            policy=h.policy,
            capabilities=h.policy.capabilities,
            expected=None,
        )
        assert new.revision != old
        with refused("shared_access_removed"):
            h.admission.capture("bob", h.namespace, policy=h.policy)

    def test_epoch_change_invalidates_token(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.share()
        old = h.admission.capture("bob", h.namespace, policy=h.policy)
        attempt = h.controls.begin("alice", h.namespace)
        h.controls.stage("alice", h.namespace, attempt, lambda: None)
        h.controls.publish("alice", h.namespace, attempt, lambda: None)
        with refused("account_changed"):
            h.admission.capture(
                "bob",
                h.namespace,
                policy=h.policy,
                context=h.admission.token(old),
                require_context=True,
            )

    def test_corruption_isolates_one_owner(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.connect("alice")
        h.connect("bob")
        h.people.store.path("alice").write_text("invalid")
        assert h.admission.capture("bob", h.namespace, policy=h.policy).owner == "bob"
        offers, unavailable = h.people.offers("bob", h.namespace, policy=h.policy)
        assert offers == [] and unavailable

    def test_identity_binding_cannot_transfer(
        self, connection_factory: Factory, tmp_path: Path
    ) -> None:
        h = connection_factory(tmp_path)
        h.people.enroll("alice", namespaces=[h.namespace])
        h.people.bind("alice", Identity("https://identity.example.com", "subject-one"))
        with refused("identity_mismatch"):
            h.restart().people.bind(
                "alice", Identity("https://identity.example.com", "subject-two")
            )
