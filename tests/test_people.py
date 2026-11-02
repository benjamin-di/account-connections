import json
import os

import pytest

from account_connections.admission import AdmissionService
from account_connections.controls import Controls
from account_connections.people import DirectoryPerson, Identity, People, Policy
from account_connections.rules import ConnectionError
from account_connections.storage import StateError


@pytest.fixture
def setup(tmp_path):
    people = People(tmp_path / "authority")
    controls = Controls(people)
    for person in ("alice", "bob"):
        people.enroll(person, namespaces=["one", "two"])
        for namespace in ("one", "two"):
            attempt = controls.begin(person, namespace)
            controls.stage(person, namespace, attempt, lambda: None)
            controls.publish(person, namespace, attempt, lambda: None)
    return people, controls, Policy("1", frozenset({"cart", "orders"}))


def share(people, policy):
    offered = people.offer(
        "alice",
        "one",
        "bob",
        policy=policy,
        capabilities=frozenset({"cart"}),
        expected=None,
    )
    people.select(
        "bob",
        "one",
        "alice",
        policy=policy,
        expected=people.namespace("bob", "one")["selection"]["revision"],
        grant_revision=offered.revision,
    )
    return offered


def test_permissions_checked_before_protected_access(setup):
    people, controls, policy = setup
    share(people, policy)
    admission = AdmissionService(people, controls, b"synthetic-key" * 3)
    assert admission.capture("bob", "one", policy=policy, capability="cart").owner == "alice"
    with pytest.raises(ConnectionError, match="capability_not_shared"):
        admission.capture("bob", "one", policy=policy, capability="orders")


def test_namespaces_never_infer_selection(setup):
    people, controls, policy = setup
    share(people, policy)
    admission = AdmissionService(people, controls, b"synthetic-key" * 3)
    with pytest.raises(ConnectionError, match="account_selection_needed"):
        admission.capture("bob", "two", policy=policy)


def test_policy_change_and_reissue_cannot_revive_selection(setup):
    people, controls, policy = setup
    offered = share(people, policy)
    updated = Policy("2", policy.capabilities)
    admission = AdmissionService(people, controls, b"synthetic-key" * 3)
    with pytest.raises(ConnectionError, match="shared_access_removed"):
        admission.capture("bob", "one", policy=updated)
    revised = people.offer(
        "alice",
        "one",
        "bob",
        policy=updated,
        capabilities=frozenset({"cart"}),
        expected=offered.revision,
    )
    assert revised.revision != offered.revision
    with pytest.raises(ConnectionError, match="shared_access_removed"):
        admission.capture("bob", "one", policy=updated)


def test_scope_change_requires_acceptance_and_invalidates_token(setup):
    people, controls, policy = setup
    offered = share(people, policy)
    admission = AdmissionService(people, controls, b"synthetic-key" * 3)
    previous = admission.capture("bob", "one", policy=policy)
    revised = people.offer(
        "alice",
        "one",
        "bob",
        policy=policy,
        capabilities=policy.capabilities,
        expected=offered.revision,
    )
    with pytest.raises(ConnectionError, match="shared_access_removed"):
        admission.capture("bob", "one", policy=policy)
    people.select(
        "bob",
        "one",
        "alice",
        policy=policy,
        expected=people.namespace("bob", "one")["selection"]["revision"],
        grant_revision=revised.revision,
    )
    with pytest.raises(StateError, match="account_changed"):
        admission.capture(
            "bob",
            "one",
            policy=policy,
            context=admission.token(previous),
            require_context=True,
        )


def test_owner_can_revoke_even_when_recipient_is_damaged(setup):
    people, _, policy = setup
    offered = share(people, policy)
    people.store.path("bob").unlink()
    people.revoke("alice", "one", "bob", expected=offered.revision)
    assert people.namespace("alice", "one")["shares"] == {}


def test_unknown_namespace_is_never_repaired(setup):
    people, _, _ = setup
    with pytest.raises(StateError, match="namespace_migration_required"):
        people.enroll("alice", namespaces=["new-publisher"])


@pytest.mark.parametrize("damage", ["symlink", "public", "duplicate", "unknown"])
def test_untrusted_record_stops_only_its_owner(setup, tmp_path, damage):
    people, _, _ = setup
    path = people.store.path("alice")
    if damage == "symlink":
        target = tmp_path / "retained.json"
        path.rename(target)
        path.symlink_to(target)
    elif damage == "public":
        path.chmod(0o644)
    elif damage == "duplicate":
        raw = path.read_text()
        path.write_text('{"version":2,' + raw[1:])
    else:
        data = json.loads(path.read_bytes())
        data["unknown"] = True
        path.write_text(json.dumps(data))
    with pytest.raises(StateError):
        people.read("alice")
    assert people.read("bob")["person"] == "bob"


def test_control_directory_symlink_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(target)
    with pytest.raises(StateError):
        People(tmp_path / "link")


def test_records_and_markers_are_private(setup):
    people, _, _ = setup
    assert os.stat(people.store.path("alice")).st_mode & 0o777 == 0o600
    assert os.stat(people.store.marker("alice")).st_mode & 0o777 == 0o600


def test_deeply_malformed_record_isolated_from_healthy_offers(setup):
    people, _, policy = setup
    people.store.path("bob").write_text("[" * 10_000 + "0" + "]" * 10_000)
    with pytest.raises(StateError):
        people.read("bob")
    assert people.offers("alice", "one", policy=policy) == ([], True)
    assert people.read("alice")["person"] == "alice"


@pytest.mark.parametrize("field", ("human_until", "attempt.expires"))
def test_oversized_numeric_record_isolated_from_healthy_offers(setup, field):
    people, controls, policy = setup
    people.enroll("charlie", namespaces=["one"])
    offered = people.offer(
        "charlie",
        "one",
        "alice",
        policy=policy,
        capabilities=frozenset({"cart"}),
        expected=None,
    )
    if field == "attempt.expires":
        controls.begin("bob", "one")
    path = people.store.path("bob")
    data = json.loads(path.read_bytes())
    control = data["namespaces"]["one"]["control"]
    if field == "human_until":
        control["human_until"] = 10**1000
    else:
        control["attempt"]["expires"] = 10**1000
    path.write_text(json.dumps(data))
    with pytest.raises(StateError):
        people.read("bob")
    offers, damaged = people.offers("alice", "one", policy=policy)
    assert damaged is True
    assert [(item["owner"], item["grant"].revision) for item in offers] == [
        ("charlie", offered.revision)
    ]
    assert people.read("charlie")["person"] == "charlie"


@pytest.mark.parametrize("token", ("é" * 64, "z" * 64, "a" * 63, ""))
def test_malformed_context_is_a_closed_mismatch(setup, token):
    people, controls, policy = setup
    share(people, policy)
    admission = AdmissionService(people, controls, b"synthetic-test-key" * 2)
    with pytest.raises(StateError, match="account_changed"):
        admission.capture("bob", "one", policy=policy, context=token, require_context=True)


def test_first_contact_enrolls_without_registry_or_implicit_selection(tmp_path):
    people = People(tmp_path / "authority")
    identity = Identity("https://identity.example.com", "subject-alice")
    row = people.contact("alice", namespaces=["example"], identity=identity, label="Alice")
    assert row["identity"] is None
    assert row["name"] == "Alice"
    assert row["namespaces"]["example"]["selection"]["choice"] is None
    people.contact("alice", namespaces=["example"], identity=identity, explicit=True)
    assert people.read("alice")["identity"] == identity.record()


def test_contact_never_transfers_subject_or_uses_label_as_identity(tmp_path):
    people = People(tmp_path / "authority")
    identity = Identity("https://identity.example.com", "subject-alice")
    people.contact("alice", namespaces=["example"], identity=identity, label="Alice", explicit=True)
    with pytest.raises(StateError, match="identity_mismatch"):
        people.contact(
            "alice",
            namespaces=["example"],
            identity=Identity(identity.issuer, "subject-other"),
            label="Alice",
            explicit=True,
        )
    assert people.read("alice")["identity"] == identity.record()


def test_display_label_is_bounded_and_header_contact_preserves_it(tmp_path):
    people = People(tmp_path / "authority")
    identity = Identity("https://identity.example.com", "subject-alice")
    people.contact("alice", namespaces=["example"], identity=identity, label="  A  " + "x" * 100)
    label = people.read("alice")["name"]
    assert len(label) == 80 and label.startswith("A ")
    people.contact("alice", namespaces=["example"])
    assert people.read("alice")["name"] == label
    people.contact("alice", namespaces=["example"], identity=identity, label=" ")
    assert people.label("alice") == "alice"


def test_signed_contact_clears_an_absent_label_and_strips_control_characters(tmp_path):
    people = People(tmp_path / "authority")
    identity = Identity("https://identity.example.com", "subject-alice")
    people.contact("alice", namespaces=["example"], identity=identity, label=" A\x00\u202elice ")
    assert people.label("alice") == "Alice"
    people.contact("alice", namespaces=["example"], identity=identity)
    assert people.label("alice") == "alice"


def test_roster_label_fallback_and_collision(tmp_path):
    people = People(tmp_path / "authority")
    people.contact("alice", namespaces=["example"], label="Reader")
    people.contact("bob", namespaces=["example"], label="Reader")
    people.contact("charlie", namespaces=["example"])
    rows = {row.id: row for row in people.roster()}
    assert rows["alice"].label == "Reader (alice)"
    assert rows["bob"].label == "Reader (bob)"
    assert rows["charlie"].label == "charlie"
    assert all(row.active and row.available for row in rows.values())


def test_roster_keeps_lost_grant_recipient_revocable(setup):
    people, _, policy = setup
    offered = share(people, policy)
    people.store.path("bob").unlink()
    people.store.marker("bob").unlink()
    rows = {row.id: row for row in people.roster()}
    assert rows["bob"].label == "bob"
    assert not rows["bob"].available and not rows["bob"].active
    people.revoke("alice", "one", "bob", expected=offered.revision)
    assert people.namespace("alice", "one")["shares"] == {}


def test_missing_group_is_durable_and_header_cannot_reactivate(setup):
    people, controls, policy = setup
    offered = share(people, policy)
    identity = Identity("https://identity.example.com", "subject-bob")
    people.bind("bob", identity)
    with pytest.raises(StateError, match="person_inactive"):
        people.contact("bob", namespaces=["one"], identity=identity, admitted=False)
    restarted = People(people.store.root)
    with pytest.raises(StateError, match="person_inactive"):
        restarted.contact("bob", namespaces=["one"])
    admission = AdmissionService(restarted, Controls(restarted), b"synthetic-key" * 3)
    with pytest.raises(StateError, match="person_inactive"):
        admission.capture("bob", "one", policy=policy)
    people.revoke("alice", "one", "bob", expected=offered.revision)
    assert people.namespace("alice", "one")["shares"] == {}


def test_only_new_sign_in_for_same_identity_resumes_inactive_person(setup):
    people, _, _ = setup
    identity = Identity("https://identity.example.com", "subject-alice")
    people.bind("alice", identity)
    people.set_inactive("alice", identity)
    with pytest.raises(StateError, match="identity_mismatch"):
        people.contact("alice", namespaces=["one"], identity=Identity(identity.issuer, "other"))
    with pytest.raises(StateError, match="person_inactive"):
        people.contact("alice", namespaces=["one"], identity=identity, label="Alice")
    people.contact("alice", namespaces=["one"], identity=identity, label="Alice", readmit=True)
    people.require_admitted("alice")
    assert people.read("alice")["identity"] == identity.record()


def test_inactive_callback_rejects_subject_mismatch(setup):
    people, _, _ = setup
    identity = Identity("https://identity.example.com", "subject-alice")
    people.bind("alice", identity)
    with pytest.raises(StateError, match="identity_mismatch"):
        people.set_inactive("alice", Identity(identity.issuer, "other"))
    people.require_admitted("alice")


def test_forget_clears_own_incoming_and_selected_authority(setup):
    people, controls, policy = setup
    share(people, policy)
    people.offer(
        "bob", "one", "alice", policy=policy, capabilities=frozenset({"cart"}), expected=None
    )
    assert people.forget("alice") == ()
    assert people.namespace("alice", "one")["shares"] == {}
    assert people.namespace("alice", "one")["selection"]["choice"] is None
    assert people.namespace("alice", "one")["control"]["state"] == "disconnected"
    assert people.namespace("bob", "one")["shares"] == {}
    assert people.namespace("bob", "one")["selection"]["choice"] is None
    with pytest.raises(StateError, match="person_inactive"):
        People(people.store.root).contact(
            "alice",
            namespaces=["one"],
            identity=Identity("https://identity.example.com", "subject-alice"),
            explicit=True,
        )


def test_forget_denies_first_even_if_cleanup_is_interrupted(setup, monkeypatch):
    people, controls, policy = setup
    share(people, policy)

    def interrupted_write(person, data):
        raise RuntimeError("synthetic process termination")

    monkeypatch.setattr(people.store, "write", interrupted_write)
    with pytest.raises(RuntimeError):
        people.forget("alice")
    restarted = People(people.store.root)
    with pytest.raises(StateError, match="person_inactive"):
        restarted.require_admitted("alice")
    admission = AdmissionService(restarted, Controls(restarted), b"synthetic-key" * 3)
    with pytest.raises(StateError, match="person_inactive"):
        admission.capture("bob", "one", policy=policy)


def test_forget_damaged_owner_remains_denied_without_repair(setup):
    people, _, policy = setup
    share(people, policy)
    people.store.path("alice").write_text("invalid")
    assert "alice" in people.forget("alice")
    with pytest.raises(StateError, match="person_inactive"):
        people.require_admitted("alice")
    assert people.namespace("bob", "one")["selection"]["choice"] is None
    assert people.store.path("alice").read_text() == "invalid"


def test_directory_is_exact_subject_and_never_runs_under_authority_lock(tmp_path):
    calls = []
    people = None

    def directory(identity):
        assert not getattr(people.store._local, "locked", False)
        calls.append(identity)
        return DirectoryPerson(True, "Directory Alice")

    people = People(tmp_path / "authority", directory=directory)
    identity = Identity("https://identity.example.com", "subject-alice")
    people.contact("alice", namespaces=["example"], identity=identity, explicit=True)
    assert people.label("alice") == "Directory Alice"
    people.refresh("alice")
    assert calls == [identity, identity]
    with people.store.lock(), pytest.raises(RuntimeError):
        people.refresh("alice")
    assert len(calls) == 2


@pytest.mark.parametrize("verdict", [None, DirectoryPerson(False)])
def test_directory_unknown_or_removed_subject_is_refused(tmp_path, verdict):
    people = People(tmp_path / "authority", directory=lambda identity: verdict)
    identity = Identity("https://identity.example.com", "subject-alice")
    with pytest.raises(StateError, match="person_inactive"):
        people.contact("alice", namespaces=["example"], identity=identity)
    assert not people.store.path("alice").exists()


def test_directory_failure_is_closed_without_leaking_error_text(tmp_path):
    def failing(identity):
        raise RuntimeError("private backend detail")

    people = People(tmp_path / "authority", directory=failing)
    with pytest.raises(StateError, match="directory_unavailable") as error:
        people.contact(
            "alice",
            namespaces=["example"],
            identity=Identity("https://identity.example.com", "subject-alice"),
        )
    assert "private" not in str(error.value)


def test_directory_positive_refresh_cannot_resurrect_inactive_person(tmp_path):
    verdict = [DirectoryPerson(True, "Alice")]
    people = People(tmp_path / "authority", directory=lambda identity: verdict[0])
    identity = Identity("https://identity.example.com", "subject-alice")
    people.contact("alice", namespaces=["example"], identity=identity, explicit=True)
    verdict[0] = DirectoryPerson(False)
    with pytest.raises(StateError, match="person_inactive"):
        people.refresh("alice")
    verdict[0] = DirectoryPerson(True, "Alice Again")
    people.refresh("alice")
    with pytest.raises(StateError, match="person_inactive"):
        people.contact("alice", namespaces=["example"])
    with pytest.raises(StateError, match="person_inactive"):
        people.contact("alice", namespaces=["example"], identity=identity)
    people.contact("alice", namespaces=["example"], identity=identity, readmit=True)
    people.require_admitted("alice")
    assert people.label("alice") == "Alice Again"


@pytest.mark.parametrize("damage", ["unknown_kind", "bad_json", "public", "symlink"])
def test_damaged_inactive_marker_stays_closed_and_isolated(setup, tmp_path, damage):
    people, _, _ = setup
    people.set_inactive("alice")
    path = people.store.root / ".inactive" / "alice.json"
    if damage == "unknown_kind":
        data = json.loads(path.read_bytes())
        data["kind"] = "active"
        path.write_text(json.dumps(data))
    elif damage == "bad_json":
        path.write_text("invalid")
    elif damage == "public":
        path.chmod(0o644)
    else:
        target = tmp_path / "retained-inactive.json"
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(StateError):
        people.require_admitted("alice")
    people.require_admitted("bob")
    rows = {row.id: row for row in people.roster()}
    assert not rows["alice"].active and rows["bob"].active


def test_forget_cannot_be_undone_by_new_verified_sign_in(setup):
    people, _, _ = setup
    identity = Identity("https://identity.example.com", "subject-alice")
    people.bind("alice", identity)
    people.forget("alice")
    with pytest.raises(StateError, match="person_inactive"):
        People(people.store.root).contact(
            "alice", namespaces=["one"], identity=identity, readmit=True, explicit=True
        )


def test_readmission_requires_a_verified_identity(tmp_path):
    people = People(tmp_path / "authority")
    with pytest.raises(ValueError):
        people.contact("alice", namespaces=["example"], readmit=True)
    assert not people.store.exists("alice")


def test_labels_cannot_impersonate_generated_collision_suffixes(setup):
    people, _, _ = setup
    people.enroll("charlie", namespaces=["one"])
    for person, label in [("alice", "Reader"), ("bob", "Reader"), ("charlie", "Reader (alice)")]:
        people.bind(person, Identity("https://identity.example.com", person), name=label)
    rows = people.roster()
    assert len({row.label.casefold() for row in rows}) == len(rows)
    assert people.label("alice") == "Reader (alice) (alice)"
    assert people.label("charlie") == "Reader (alice) (charlie)"


def test_case_distinct_identifiers_have_unique_finite_labels(setup):
    people, _, _ = setup
    people.enroll("ALICE", namespaces=["one"])
    people.enroll("charlie", namespaces=["one"])
    for person, label in [
        ("alice", "Reader"),
        ("ALICE", "Reader"),
        ("charlie", "Reader (alice) (alice) [1]"),
    ]:
        people.bind(person, Identity("https://identity.example.com", person), name=label)
    rows = people.roster()
    assert len({row.label.casefold() for row in rows}) == len(rows)
    assert people.label("alice") == "Reader (alice) (alice) [2]"
    assert people.label("ALICE") == "Reader (ALICE) (ALICE)"
