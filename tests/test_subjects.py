"""Immutable first-contact resolution with synthetic identities and retained controls."""

import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

import pytest

from account_connections import subjects
from account_connections.migrations import amazon as migrate_amazon
from account_connections.people import DirectoryPerson, Identity, People
from account_connections.storage import StateError
from account_connections.subjects import Subjects

A = Identity("https://identity.example.com", "first-subject")
B = Identity("https://identity.example.com", "second-subject")
OTHER_ISSUER = Identity("https://other.example.com", A.subject)


def resolve(people, identity=A):
    return Subjects(people).resolve(
        identity, namespaces=["orders"], retained_credentials=lambda _: False
    )


def empty(tmp_path):
    people = People(tmp_path / "people")
    Subjects(people).initialize([], retained_credentials=False)
    return people


def test_fresh_subjects_converge_across_restarts_without_selection(tmp_path):
    people = empty(tmp_path)
    first = resolve(people)
    assert resolve(People(people.store.root)) == first
    second = resolve(people, B)
    assert first != second
    assert len(first) == 32 and first.startswith("p")
    for person, identity in ((first, A), (second, B)):
        data = people.contact(person, namespaces=["orders"], identity=identity)
        assert data["identity"] == identity.record()
        assert data["namespaces"]["orders"]["control"]["state"] == "disconnected"
        assert data["namespaces"]["orders"]["selection"]["choice"] is None
        assert data["namespaces"]["orders"]["shares"] == {}


def test_issuer_is_part_of_identity(tmp_path):
    people = empty(tmp_path)
    assert resolve(people) != resolve(people, OTHER_ISSUER)


@pytest.mark.parametrize("retained", [False, True])
def test_bootstrap_cannot_omit_interrupted_native_migration(tmp_path, monkeypatch, retained):
    people = People(tmp_path / "people")
    people.enroll("alpha", namespaces=["orders"], identity=A)
    original = people.store.write

    def interrupted(person, data):
        if person == "bravo":
            raise InterruptedError("synthetic crash before destination publication")
        original(person, data)

    with monkeypatch.context() as patch:
        patch.setattr(people.store, "write", interrupted)
        with pytest.raises(InterruptedError):
            migrate_amazon(
                people,
                "bravo",
                {"orders": {"revision": "retained-revision", "phase": 2, "human_until": 123}},
                identity=B,
            )
    before = {
        path: path.read_bytes()
        for name in (".migrations", ".snapshots")
        for path in (people.store.root / name).iterdir()
    }
    subjects = Subjects(people)
    with pytest.raises(StateError, match="subject_migration_required"):
        subjects.initialize([(A, "alpha")], retained_credentials=retained)
    assert not subjects.marker.exists()
    assert not subjects.path.exists()
    assert all(path.read_bytes() == value for path, value in before.items())


def test_lookup_never_enrolls_a_denied_or_pending_identity(tmp_path):
    people = empty(tmp_path)
    subjects = Subjects(people)
    before = subjects.path.read_bytes()
    assert subjects.lookup(A) is None
    assert subjects.path.read_bytes() == before
    assert people.store.people() == []
    person = resolve(people)
    assert subjects.lookup(A) == person
    people.set_inactive(person, A)
    assert subjects.lookup(A) == person
    with pytest.raises(StateError, match="person_inactive"):
        people.require_admitted(person)
    index = json.loads(subjects.path.read_text())
    next(iter(index["owners"].values()))["state"] = "pending"
    subjects.path.write_text(json.dumps(index))
    assert subjects.lookup(A) is None


def test_lookup_requires_selected_authority_but_ignores_unrelated_corruption(tmp_path):
    people = empty(tmp_path)
    first, second = resolve(people), resolve(people, B)
    people.store.path(second).write_text("broken")
    assert Subjects(people).lookup(A) == first
    with pytest.raises(StateError):
        Subjects(people).lookup(B)
    people.store.path(first).unlink()
    with pytest.raises(StateError):
        Subjects(people).lookup(A)


def test_installed_aliases_and_all_namespace_data_are_preserved(tmp_path):
    people = People(tmp_path / "people")
    people.enroll("legacy", namespaces=["orders"], identity=A)
    with people.store.edit("legacy") as row:
        row["namespaces"]["orders"]["metadata"] = {"budget": 37, "generation": 9}
    before = people.store.path("legacy").read_bytes()
    owners = Subjects(people)
    owners.initialize([(A, "legacy")], retained_credentials=True)
    assert resolve(people) == "legacy"
    assert people.store.path("legacy").read_bytes() == before
    assert resolve(people, B) != "legacy"


def test_explicit_migration_can_pin_an_unbound_alias_without_rewriting_controls(tmp_path):
    people = People(tmp_path / "people")
    people.enroll("legacy", namespaces=["orders"])
    before = people.store.path("legacy").read_bytes()
    Subjects(people).initialize([(A, "legacy")], retained_credentials=True)
    assert resolve(people) == "legacy"
    assert people.store.path("legacy").read_bytes() == before
    people.contact("legacy", namespaces=["orders"], identity=A, explicit=True)
    assert people.read("legacy")["identity"] == A.record()


def test_unrelated_corrupt_control_does_not_block_an_existing_owner(tmp_path):
    people = People(tmp_path / "people")
    for person, identity in (("alpha", A), ("bravo", B)):
        people.enroll(person, namespaces=["orders"], identity=identity)
    Subjects(people).initialize([(A, "alpha"), (B, "bravo")], retained_credentials=True)
    people.store.path("bravo").write_text("broken")
    assert resolve(people) == "alpha"
    with pytest.raises(StateError):
        resolve(people, B)


@pytest.mark.parametrize("stop", ["inactive", "forgotten"])
def test_resolution_does_not_readmit_or_recreate_departed_users(tmp_path, stop):
    people = empty(tmp_path)
    person = resolve(people)
    if stop == "inactive":
        people.set_inactive(person, A)
    else:
        people.forget(person)
    assert resolve(people) == person
    with pytest.raises(StateError, match="person_inactive"):
        people.contact(person, namespaces=["orders"], identity=A)
    if stop == "forgotten":
        with pytest.raises(StateError, match="person_inactive"):
            people.contact(person, namespaces=["orders"], identity=A, explicit=True, readmit=True)
    else:
        people.contact(person, namespaces=["orders"], identity=A, explicit=True, readmit=True)


def test_current_directory_denial_remains_authoritative(tmp_path):
    people = empty(tmp_path)
    person = resolve(people)
    people.directory = lambda _: DirectoryPerson(False)
    with pytest.raises(StateError, match="person_inactive"):
        people.contact(person, namespaces=["orders"], identity=A)
    people.directory = lambda _: DirectoryPerson(True)
    assert resolve(people) == person
    with pytest.raises(StateError, match="person_inactive"):
        people.contact(person, namespaces=["orders"], identity=A)


@pytest.mark.parametrize("part", ["record", "record_and_marker", "index", "index_marker"])
def test_missing_adopted_authority_is_never_reconstructed(tmp_path, part):
    people = empty(tmp_path)
    person = resolve(people)
    if part.startswith("record"):
        people.store.path(person).unlink()
        if part == "record_and_marker":
            people.store.marker(person).unlink()
    elif part == "index":
        Subjects(people).path.unlink()
    else:
        Subjects(people).marker.unlink()
    with pytest.raises(StateError):
        resolve(people)
    if part == "index":
        with pytest.raises(StateError):
            Subjects(people).initialize([], retained_credentials=False)
    if part.startswith("record"):
        assert not people.store.path(person).exists()


def test_migration_requires_complete_unique_verified_bindings(tmp_path):
    people = People(tmp_path / "people")
    people.enroll("legacy", namespaces=["orders"], identity=A)
    for bindings in ([], [(B, "legacy")], [(A, "legacy"), (A, "extra")]):
        with pytest.raises(StateError):
            Subjects(people).initialize(bindings, retained_credentials=True)
    assert not Subjects(people).path.exists()


def test_unknown_external_credentials_prevent_empty_bootstrap_and_enrollment(tmp_path):
    people = People(tmp_path / "people")
    owners = Subjects(people)
    with pytest.raises(StateError, match="subject_migration_required"):
        owners.initialize([], retained_credentials=True)
    owners.initialize([], retained_credentials=False)
    with pytest.raises(StateError, match="subject_enrollment_refused"):
        owners.resolve(A, namespaces=["orders"], retained_credentials=lambda _: True)
    assert people.store.people() == []


def test_pending_owner_retries_after_crash_before_record_creation(tmp_path, monkeypatch):
    people = empty(tmp_path)
    owners = Subjects(people)
    original = owners._write

    def interrupted(rows):
        original(rows)
        raise InterruptedError()

    monkeypatch.setattr(owners, "_write", interrupted)
    with pytest.raises(InterruptedError):
        owners.resolve(A, namespaces=["orders"], retained_credentials=lambda _: False)
    assert people.store.people() == []
    monkeypatch.setattr(owners, "_write", original)
    person = resolve(people)
    assert resolve(people) == person
    assert len(people.store.people()) == 1


def test_pending_owner_retries_after_record_is_persisted(tmp_path, monkeypatch):
    people = empty(tmp_path)
    original = people.store.write

    def interrupted(person, data):
        original(person, data)
        raise InterruptedError()

    monkeypatch.setattr(people.store, "write", interrupted)
    with pytest.raises(InterruptedError):
        resolve(people)
    (person,) = people.store.people()
    before = people.store.path(person).read_bytes()
    monkeypatch.setattr(people.store, "write", original)
    assert resolve(people) == person
    assert people.store.path(person).read_bytes() == before


def test_pending_changed_controls_cannot_be_accepted_as_fresh(tmp_path, monkeypatch):
    people = empty(tmp_path)
    owners = Subjects(people)
    original = owners._write
    count = 0

    def interrupted(rows):
        nonlocal count
        count += 1
        if count == 2:
            raise InterruptedError()
        original(rows)

    monkeypatch.setattr(owners, "_write", interrupted)
    with pytest.raises(InterruptedError):
        owners.resolve(A, namespaces=["orders"], retained_credentials=lambda _: False)
    (person,) = people.store.people()
    with people.store.edit(person) as row:
        row["namespaces"]["orders"]["metadata"] = {"retained": True}
    monkeypatch.setattr(owners, "_write", original)
    with pytest.raises(StateError, match="subject_enrollment_refused"):
        resolve(people)


def _process_contact(root, identity):
    people = People(root)
    return resolve(people, identity)


def test_concurrent_processes_converge_without_shared_or_duplicate_owners(tmp_path):
    people = empty(tmp_path)
    identities = [A, B] * 6
    with ProcessPoolExecutor(4, mp_context=multiprocessing.get_context("spawn")) as pool:
        result = list(pool.map(_process_contact, [people.store.root] * len(identities), identities))
    assert len(set(result[::2])) == len(set(result[1::2])) == 1
    assert result[0] != result[1]
    assert len(people.store.people()) == 2


def test_index_change_cannot_transfer_retained_owner(tmp_path):
    people = empty(tmp_path)
    person = resolve(people)
    owners = Subjects(people)
    value = json.loads(owners.path.read_text())
    row = next(iter(value["owners"].values()))
    row["identity"] = B.record()
    owners.path.write_text(json.dumps(value))
    with pytest.raises(StateError):
        resolve(people, B)
    assert people.read(person)["identity"] == A.record()


def test_departure_marker_cannot_hide_lost_controls_on_readmission(tmp_path):
    people = empty(tmp_path)
    person = resolve(people)
    people.set_inactive(person, A)
    people.store.path(person).unlink()
    people.store.marker(person).unlink()
    with pytest.raises(StateError, match="subject_authority_missing"):
        resolve(people)
    assert not people.store.path(person).exists()


def test_truncated_identifier_collision_refuses_instead_of_reusing_owner(tmp_path, monkeypatch):
    keys = {A: "a" * 64, B: "a" * 31 + "b" * 33}
    monkeypatch.setattr(subjects, "_key", keys.__getitem__)
    people = empty(tmp_path)
    first = resolve(people)
    with pytest.raises(StateError, match="subject_enrollment_refused"):
        resolve(people, B)
    assert people.read(first)["identity"] == A.record()


def test_capacity_refuses_new_subject_without_affecting_existing_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(subjects, "MAX_PEOPLE", 2)
    people = empty(tmp_path)
    first = resolve(people)
    resolve(people, B)
    with pytest.raises(StateError, match="subject_enrollment_refused"):
        resolve(people, OTHER_ISSUER)
    assert resolve(people) == first


def test_credential_census_receives_exact_person_and_is_not_run_for_retained_owner(tmp_path):
    people = empty(tmp_path)
    seen = []

    def census(person):
        seen.append(person)
        return False

    owners = Subjects(people)
    first = owners.resolve(A, namespaces=["orders"], retained_credentials=census)
    assert seen == [first]
    assert owners.resolve(A, namespaces=["orders"], retained_credentials=census) == first
    assert seen == [first]


@pytest.mark.parametrize("corruption", ["marker_boolean", "index_boolean", "symlink"])
def test_unreadable_or_invalid_index_denies_without_repair(tmp_path, corruption):
    people = empty(tmp_path)
    owners = Subjects(people)
    if corruption == "marker_boolean":
        owners.marker.write_text('{"version":true}')
    elif corruption == "index_boolean":
        owners.path.write_text('{"version":true,"owners":{}}')
    else:
        target = tmp_path / "target"
        owners.path.rename(target)
        owners.path.symlink_to(target)
    with pytest.raises(StateError):
        resolve(people)
    assert people.store.people() == []


def test_explicit_bootstrap_finishes_its_exact_interrupted_plan(tmp_path, monkeypatch):
    people = People(tmp_path / "people")
    owners = Subjects(people)
    original = subjects.atomic_json

    def interrupted(path, data):
        if path == owners.marker:
            raise InterruptedError()
        original(path, data)

    monkeypatch.setattr(subjects, "atomic_json", interrupted)
    with pytest.raises(InterruptedError):
        owners.initialize([], retained_credentials=False)
    with pytest.raises(StateError):
        resolve(people)
    monkeypatch.setattr(subjects, "atomic_json", original)
    owners.initialize([], retained_credentials=False)
    assert resolve(people)
