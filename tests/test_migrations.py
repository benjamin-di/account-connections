import copy
import json

import pytest

from account_connections import migrations
from account_connections.people import Identity, People, Policy
from account_connections.storage import StateError

POLICY = Policy("1", frozenset({"shopping", "history", "subscription"}))


def hktv_record():
    return {
        "version": 2,
        "epoch": "synthetic-epoch",
        "state": "disconnected",
        "owner": {"issuer": "https://identity.example.com", "sub": "subject-one"},
        "provider_email": "alice@example.com",
        "generation": 8,
        "name": "Alice",
        "shares": {"bob": {"revision": "synthetic-grant", "order_history": True}},
        "shared_with": ["bob"],
        "selection": {"account": "alice", "grant": None},
        "selection_revision": "synthetic-selection",
    }


def test_hktv_preserves_authority_and_snapshot(tmp_path):
    people = People(tmp_path / "authority")
    source = hktv_record()
    data = migrations.hktvmall(people, "alice", source, policy=POLICY)
    row = data["namespaces"]["default"]
    assert data["identity"] == source["owner"]
    assert row["control"]["epoch"] == "synthetic-epoch"
    assert row["control"]["state"] == "disconnected"
    assert row["control"]["generation"] == 8
    assert row["selection"]["revision"] == "synthetic-selection"
    assert row["shares"]["bob"]["revision"] == "synthetic-grant"
    assert row["shares"]["bob"]["capabilities"] == ["history", "shopping"]
    assert json.loads((people.store.root / ".snapshots/alice.json").read_text()) == source
    people.bind("alice", Identity("https://identity.example.com", "subject-one"), name="Updated")
    # A repeat never overwrites subsequent canonical changes.
    assert migrations.hktvmall(people, "alice", source, policy=POLICY)["name"] == "Updated"


@pytest.mark.parametrize(
    "phase,state", [(0, "active"), (1, "disconnected"), (2, "disconnecting"), (3, "reconnecting")]
)
def test_amazon_preserves_each_marketplace_phase(tmp_path, phase, state):
    people = People(tmp_path / "authority")
    source = {"example": {"revision": "synthetic-revision", "phase": phase, "human_until": 123}}
    data = migrations.amazon(people, "alice", source)
    row = data["namespaces"]["example"]
    assert row["control"]["revision"] == "synthetic-revision"
    assert row["control"]["state"] == state
    assert row["selection"]["choice"] == {"owner": "alice", "grant": None}


def test_newsclip_preserves_namespace_selection_and_grants(tmp_path):
    people = People(tmp_path / "authority")
    access = {
        "version": 1,
        "providers": {
            "publisher": {
                "selection": {"owner": "bob", "grant": "selected-grant"},
                "revision": "selection-revision",
                "grants": {"charlie": "offered-grant"},
            }
        },
    }
    controls = {"publisher": {"revision": "control-revision", "phase": 0}}
    data = migrations.newsclip(people, "alice", access, controls, policy=POLICY)
    row = data["namespaces"]["publisher"]
    assert row["selection"] == {
        "choice": {"owner": "bob", "grant": "selected-grant"},
        "revision": "selection-revision",
    }
    assert row["shares"]["charlie"]["revision"] == "offered-grant"
    assert row["control"]["revision"] == "control-revision"


@pytest.mark.parametrize("crash_after", [1, 2, 3, 4])
def test_interrupted_migration_resumes_from_same_snapshot(tmp_path, monkeypatch, crash_after):
    people = People(tmp_path / "authority")
    source = hktv_record()
    actual_atomic = migrations.atomic_json
    actual_write = people.store.write
    writes = [0]

    def maybe_crash():
        writes[0] += 1
        if writes[0] == crash_after:
            raise RuntimeError("synthetic process termination")

    def atomic(path, value):
        actual_atomic(path, value)
        maybe_crash()

    def write(person, value):
        actual_write(person, value)
        maybe_crash()

    monkeypatch.setattr(migrations, "atomic_json", atomic)
    monkeypatch.setattr(people.store, "write", write)
    with pytest.raises(RuntimeError):
        migrations.hktvmall(people, "alice", source, policy=POLICY)
    monkeypatch.setattr(migrations, "atomic_json", actual_atomic)
    monkeypatch.setattr(people.store, "write", actual_write)
    result = migrations.hktvmall(people, "alice", source, policy=POLICY)
    assert result["namespaces"]["default"]["control"]["generation"] == 8


def test_incomplete_migration_blocks_runtime(tmp_path, monkeypatch):
    people = People(tmp_path / "authority")
    actual_atomic = migrations.atomic_json

    def atomic(path, value):
        if value.get("state") == "complete":
            raise RuntimeError("synthetic process termination")
        actual_atomic(path, value)

    monkeypatch.setattr(migrations, "atomic_json", atomic)
    with pytest.raises(RuntimeError):
        migrations.hktvmall(people, "alice", hktv_record(), policy=POLICY)
    with pytest.raises(StateError):
        people.read("alice")


def test_completed_migration_cannot_repair_lost_record(tmp_path):
    people = People(tmp_path / "authority")
    source = hktv_record()
    migrations.hktvmall(people, "alice", source, policy=POLICY)
    people.store.path("alice").unlink()
    with pytest.raises(StateError):
        migrations.hktvmall(people, "alice", source, policy=POLICY)


def test_migration_refuses_source_changes(tmp_path):
    people = People(tmp_path / "authority")
    source = hktv_record()
    migrations.hktvmall(people, "alice", source, policy=POLICY)
    changed = copy.deepcopy(source)
    changed["generation"] += 1
    with pytest.raises(StateError, match="migration_source_changed"):
        migrations.hktvmall(people, "alice", changed, policy=POLICY)


def test_migration_rejects_credential_fields(tmp_path):
    people = People(tmp_path / "authority")
    with pytest.raises(StateError, match="migration_source_invalid"):
        migrations.amazon(
            people, "alice", {"example": {"revision": "r", "phase": 0, "cookies": []}}
        )


@pytest.mark.parametrize("extra", ({"cookies": ["invented"]}, {"password": "invented"}))
def test_newsclip_rejects_unknown_controls_before_snapshot(tmp_path, extra):
    people = People(tmp_path / "authority")
    access = {
        "version": 1,
        "providers": {"publisher": {"selection": None, "revision": "r", "grants": {}}},
    }
    controls = {"publisher": {"revision": "r", "phase": 0, **extra}}
    with pytest.raises(StateError, match="migration_source_invalid"):
        migrations.newsclip(people, "alice", access, controls, policy=POLICY)
    assert not (people.store.root / ".snapshots").exists()
    assert not people.store.exists("alice")


@pytest.mark.parametrize("crash_after", [1, 2, 3, 4])
def test_amazon_paths_publish_before_completion_and_resume(tmp_path, monkeypatch, crash_after):
    people = People(tmp_path / "authority")
    native = {"example": {"revision": "r", "phase": 0}}
    metadata = {
        "example": {
            "jar_path": "/state/cookies.json",
            "keeper_path": "/state/keeper.json",
            "default_site": "example",
        }
    }
    actual_atomic, actual_write = migrations.atomic_json, people.store.write
    writes = 0

    def crash():
        nonlocal writes
        writes += 1
        if writes == crash_after:
            raise RuntimeError("synthetic termination")

    def atomic(path, value):
        if value.get("state") == "complete":
            assert (
                json.loads(people.store.path("alice").read_text())["namespaces"]["example"][
                    "metadata"
                ]
                == metadata["example"]
            )
        actual_atomic(path, value)
        crash()

    def write(person, value):
        actual_write(person, value)
        crash()

    monkeypatch.setattr(migrations, "atomic_json", atomic)
    monkeypatch.setattr(people.store, "write", write)
    with pytest.raises(RuntimeError):
        migrations.amazon(people, "alice", native, metadata=metadata)
    monkeypatch.setattr(migrations, "atomic_json", actual_atomic)
    monkeypatch.setattr(people.store, "write", actual_write)
    assert (
        migrations.amazon(people, "alice", native, metadata=metadata)["namespaces"]["example"][
            "metadata"
        ]
        == metadata["example"]
    )
    changed = copy.deepcopy(metadata)
    changed["example"]["keeper_path"] = "/state/new.json"
    with pytest.raises(StateError, match="migration_source_changed"):
        migrations.amazon(people, "alice", native, metadata=changed)


@pytest.mark.parametrize(
    "metadata",
    [
        {"unknown": {}},
        {"example": {}},
        {"example": {"cookies": "secret"}},
        {
            "example": {
                "jar_path": [],
                "keeper_path": "/state/keeper.json",
                "default_site": "example",
            }
        },
    ],
)
def test_amazon_routing_metadata_rejects_unknown_or_invalid_fields(tmp_path, metadata):
    people = People(tmp_path / "authority")
    with pytest.raises(StateError, match="migration_source_invalid"):
        migrations.amazon(
            people, "alice", {"example": {"revision": "r", "phase": 0}}, metadata=metadata
        )
    assert not (people.store.root / ".snapshots").exists()
