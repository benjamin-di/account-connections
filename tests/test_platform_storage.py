"""Native process tests for the authority backend, never provider integration."""

import importlib
import multiprocessing
import os
import subprocess
import sys
from pathlib import Path

import pytest

from account_connections import _platform, storage
from account_connections.controls import Controls
from account_connections.people import People
from account_connections.storage import StateError, Store, read_json


def _make_backend(spec):
    module, name = spec.split(":")
    return getattr(importlib.import_module(module), name)()


def _install_backend(spec):
    candidate = _make_backend(spec)
    storage.backend = lambda: candidate


def _hold_operation(spec, root, exclusive, connection):
    _install_backend(spec)
    controls = Controls(People(Path(root)))
    with controls.operation("alice", "one", exclusive=exclusive):
        connection.send("held")
        if connection.recv() == "crash":
            os._exit(23)


def _hold_admission(spec, root, connection):
    _install_backend(spec)
    controls = Controls(People(Path(root)))
    with controls.admitted("alice", "one"):
        connection.send("held")
        connection.recv()


def _increment(spec, root, iterations):
    _install_backend(spec)
    store = Store(Path(root))
    for _ in range(iterations):
        with store.edit("alice") as row:
            row["counter"] += 1


def _crash_publication(spec, root):
    _install_backend(spec)
    controls = Controls(People(Path(root)))
    attempt = controls.begin("alice", "one")
    controls.stage("alice", "one", attempt, lambda: None)
    controls.publish("alice", "one", attempt, lambda: os._exit(23))


def _join(process):
    process.join(10)
    if process.is_alive():
        process.kill()
        process.join(5)
        pytest.fail("storage subprocess did not finish")


@pytest.fixture
def backend_spec(request):
    specified = request.config.getoption("--authority-test-backend")
    if specified:
        return specified
    if os.name != "posix":
        pytest.skip("no qualified authority backend on this platform")
    return "account_connections._posix:PosixBackend"


@pytest.fixture
def controls(tmp_path, backend_spec, monkeypatch):
    # Spawned children install the same explicit factory independently. Patching
    # only this process would accidentally test the registered backend in children.
    candidate = _make_backend(backend_spec)
    monkeypatch.setattr(storage, "backend", lambda: candidate)
    people = People(tmp_path / "authority")
    people.enroll("alice", namespaces=["one", "two"])
    return Controls(people)


@pytest.fixture
def held_process(backend_spec):
    children = []

    def start(target, *arguments):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(target=target, args=(backend_spec, *arguments, child))
        process.start()
        child.close()
        children.append((process, parent))
        assert parent.poll(10), "subprocess did not acquire its lock"
        assert parent.recv() == "held"
        return process, parent

    yield start
    for process, connection in children:
        try:
            if process.is_alive():
                connection.send("release")
            _join(process)
        finally:
            connection.close()


def _connect(controls):
    attempt = controls.begin("alice", "one")
    controls.stage("alice", "one", attempt, lambda: None)
    controls.publish("alice", "one", attempt, lambda: None)


@pytest.mark.parametrize(
    "held_exclusive,requested_exclusive", [(True, True), (True, False), (False, True)]
)
def test_independent_processes_exclude_conflicting_operations(
    controls, held_process, held_exclusive, requested_exclusive
):
    held_process(_hold_operation, str(controls.store.root), held_exclusive)
    with (
        pytest.raises(StateError, match="connection_busy"),
        controls.operation("alice", "one", exclusive=requested_exclusive, timeout=0),
    ):
        pytest.fail("conflicting process was admitted")
    # A lock on one namespace does not serialize unrelated provider work.
    with controls.operation("alice", "two", timeout=0):
        pass


def test_independent_processes_share_read_borrows(controls, held_process):
    held_process(_hold_operation, str(controls.store.root), False)
    with controls.operation("alice", "one", exclusive=False, timeout=0):
        pass


@pytest.mark.parametrize("exclusive", [False, True])
def test_operation_lock_releases_after_abrupt_process_exit(controls, held_process, exclusive):
    process, connection = held_process(_hold_operation, str(controls.store.root), exclusive)
    connection.send("crash")
    _join(process)
    assert process.exitcode == 23
    with controls.operation("alice", "one", timeout=0):
        pass


def test_authority_updates_serialize_across_spawned_processes(controls, backend_spec):
    with controls.store.lock():
        row = controls.store.read("alice")
        row["counter"] = 0
        controls.store.write("alice", row)
    context = multiprocessing.get_context("spawn")
    children = [
        context.Process(target=_increment, args=(backend_spec, str(controls.store.root), 12))
        for _ in range(4)
    ]
    try:
        for process in children:
            process.start()
        for process in children:
            _join(process)
            assert process.exitcode == 0
    finally:
        for process in children:
            if process.pid and process.is_alive():
                process.kill()
                process.join(5)
    assert controls.store.read("alice")["counter"] == 48


def test_authority_lock_keeps_reentrant_writes_inside_outer_scope(controls):
    with controls.store.lock():
        with controls.store.lock():
            row = controls.store.read("alice")
        row["counter"] = 1
        controls.store.write("alice", row)
    assert controls.store.read("alice")["counter"] == 1


def test_shared_operation_cannot_upgrade_through_nested_backend_use(controls):
    with (
        controls.operation("alice", "one", exclusive=False),
        controls.operation("alice", "one", exclusive=False),
        pytest.raises(StateError, match="publication_requires_exclusive"),
        controls.operation("alice", "one", timeout=0),
    ):
        pytest.fail("nested shared lock was upgraded")


def test_abrupt_writer_exit_keeps_published_authority_stopped(controls, backend_spec):
    _connect(controls)
    old_epoch = controls.status("alice", "one")["epoch"]
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_publication, args=(backend_spec, str(controls.store.root))
    )
    process.start()
    _join(process)
    assert process.exitcode == 23
    restarted = Controls(People(controls.store.root))
    assert restarted.status("alice", "one")["epoch"] != old_epoch
    assert restarted.status("alice", "one")["state"] == "reconnecting"
    with pytest.raises(StateError, match="owner_reconnect"):
        restarted.require_active("alice", "one")


def test_disconnect_drains_other_process_before_provider_deletion(controls, held_process):
    _connect(controls)
    process, connection = held_process(_hold_admission, str(controls.store.root))
    barrier = controls.suspend("alice", "one")
    deleted = []
    with pytest.raises(StateError, match="connection_busy"):
        controls.finish_disconnect("alice", "one", barrier, lambda: deleted.append(True), timeout=0)
    assert not deleted
    connection.send("release")
    _join(process)
    assert process.exitcode == 0
    assert controls.finish_disconnect("alice", "one", barrier, lambda: deleted.append(True))
    assert deleted == [True]


@pytest.mark.parametrize("platform", ["nt", "java", "unknown"])
def test_unqualified_platform_rejects_before_creating_authority(tmp_path, monkeypatch, platform):
    monkeypatch.setattr(storage, "backend", lambda: _platform._select_backend(platform))
    root = tmp_path / "authority"
    with pytest.raises(StateError, match="unsupported_storage_platform"):
        Store(root)
    assert not root.exists()


def test_optional_authority_modules_import_without_loading_posix_backend():
    source = r"""
import importlib.abc
import sys

class NoPosix(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ("fcntl", "account_connections._posix"):
            raise AssertionError("optional import selected a POSIX backend")

sys.meta_path.insert(0, NoPosix())
import account_connections
import account_connections.people
import account_connections.controls
import account_connections.migrations
assert "fcntl" not in sys.modules
assert "account_connections._posix" not in sys.modules
"""
    subprocess.run([sys.executable, "-c", source], check=True, timeout=15)


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory flush instrumentation")
def test_atomic_records_and_durable_removal_use_same_backend(tmp_path, monkeypatch):
    from account_connections._posix import PosixBackend

    backend = PosixBackend()
    synced = []
    actual = backend._sync_directory

    def sync(path):
        synced.append(path)
        actual(path)

    monkeypatch.setattr(backend, "_sync_directory", sync)
    monkeypatch.setattr(storage, "backend", lambda: backend)
    root = tmp_path / "authority"
    backend.directory(root)
    path = root / "synthetic.json"
    storage.atomic_json(path, {"value": 1})
    assert read_json(path) == {"value": 1}
    storage.durable_unlink(path)
    assert not path.exists()
    assert synced == [path.parent, path.parent]


@pytest.mark.parametrize(
    "identifiers",
    [("Alice", "alice"), ("CON", "con"), ("record", "record."), ("a" * 128, "A" * 128)],
)
def test_exact_identifiers_keep_independent_records_and_markers(controls, identifiers):
    people = controls.people
    for person in identifiers:
        people.enroll(person, namespaces=["one"])
    assert set(identifiers) <= set(controls.store.people())
    for index, person in enumerate(identifiers):
        with controls.store.edit(person) as row:
            row["synthetic_counter"] = index
    for index, person in enumerate(identifiers):
        assert controls.store.read(person)["person"] == person
        assert controls.store.read(person)["synthetic_counter"] == index
        assert controls.store.marker(person).exists()
