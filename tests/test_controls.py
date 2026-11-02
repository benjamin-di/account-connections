import threading

import pytest

from account_connections.controls import Controls
from account_connections.people import People
from account_connections.storage import StateError


@pytest.fixture
def controls(tmp_path):
    people = People(tmp_path / "authority")
    people.enroll("alice", namespaces=["one", "two"])
    return Controls(people)


def connect(controls, namespace="one"):
    attempt = controls.begin("alice", namespace)
    controls.stage("alice", namespace, attempt, lambda: None)
    return controls.publish("alice", namespace, attempt, lambda: None)


def test_new_owner_requires_explicit_connection(controls):
    with pytest.raises(StateError, match="owner_reconnect"):
        controls.require_active("alice", "one")


def test_stage_cannot_publish_other_namespace(controls):
    attempt = controls.begin("alice", "one")
    writes = []
    with pytest.raises(StateError):
        controls.stage("alice", "two", attempt, lambda: writes.append(True))
    assert not writes


def test_cancel_stale_form_cannot_cancel_replacement(controls):
    first = controls.begin("alice", "one")
    second = controls.begin("alice", "one")
    assert not controls.cancel("alice", "one", first)
    assert controls.current("alice", "one", second)


def test_stale_cleanup_does_not_upgrade_an_admitted_borrow(controls):
    connect(controls)
    stale = controls.begin("alice", "one")
    current = controls.begin("alice", "one")
    with controls.admitted("alice", "one"):
        assert not controls.cancel("alice", "one", stale)
        assert not controls.finish_disconnect(
            "alice", "one", stale, lambda: pytest.fail("stale cleanup")
        )
    assert controls.current("alice", "one", current)


def test_cleanup_allows_a_new_barrier_without_closing_it(controls):
    connect(controls)
    first = controls.suspend("alice", "one")
    cleaning, replaced = threading.Event(), threading.Event()
    failures = []

    def newer_barrier():
        if not cleaning.wait(2):
            failures.append("cleanup never started")
            return
        controls.suspend("alice", "one")
        replaced.set()

    worker = threading.Thread(target=newer_barrier, daemon=True)
    worker.start()

    def cleanup():
        cleaning.set()
        assert replaced.wait(2), "cleanup held the authority lock"

    try:
        assert not controls.finish_disconnect("alice", "one", first, cleanup)
    finally:
        worker.join(timeout=2)
    assert not worker.is_alive() and not failures
    current = controls.status("alice", "one")
    assert current["state"] == "disconnecting" and current["revision"] != first


def test_expired_attempt_cannot_stage_or_publish(tmp_path):
    now = [100.0]
    people = People(tmp_path / "authority", clock=lambda: now[0])
    people.enroll("alice", namespaces=["one"])
    controls = Controls(people)
    attempt = controls.begin("alice", "one", ttl=1)
    now[0] += 2
    with pytest.raises(StateError):
        controls.stage("alice", "one", attempt, lambda: pytest.fail("stale writer"))
    with pytest.raises(StateError):
        controls.publish("alice", "one", attempt, lambda: pytest.fail("stale writer"))


def test_maintenance_stops_during_human_attempt(controls):
    connect(controls)
    attempt = controls.begin("alice", "one")
    assert controls.maintenance_blocker("alice", "one") == "connection_interactive"
    with pytest.raises(StateError):
        controls.require_maintenance("alice", "one")
    controls.cancel("alice", "one", attempt)
    assert controls.maintenance_blocker("alice", "one") is None


def test_failed_writer_keeps_durable_barrier(controls):
    old_epoch = connect(controls)
    attempt = controls.begin("alice", "one")
    controls.stage("alice", "one", attempt, lambda: None)

    def crash():
        raise RuntimeError("synthetic interrupted credential replacement")

    with pytest.raises(RuntimeError):
        controls.publish("alice", "one", attempt, crash)
    restarted = Controls(People(controls.store.root))
    assert restarted.status("alice", "one")["epoch"] != old_epoch
    with pytest.raises(StateError):
        restarted.require_active("alice", "one")


def test_suspend_immediate_then_drain_before_delete(controls):
    connect(controls)
    admitted = threading.Event()
    finish = threading.Event()
    errors = []

    def borrow():
        try:
            with controls.admitted("alice", "one"):
                admitted.set()
                assert finish.wait(5)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=borrow)
    worker.start()
    assert admitted.wait(5)
    barrier = controls.suspend("alice", "one")
    deleted = []
    with pytest.raises(StateError, match="connection_busy"):
        controls.finish_disconnect("alice", "one", barrier, lambda: deleted.append(True), timeout=0)
    with pytest.raises(StateError, match="owner_reconnect"):
        controls.require_active("alice", "one")
    assert not deleted
    finish.set()
    worker.join(5)
    assert not worker.is_alive() and not errors
    assert controls.finish_disconnect("alice", "one", barrier, lambda: deleted.append(True))
    assert deleted == [True]
    assert controls.status("alice", "one")["state"] == "disconnected"


def test_missing_native_delete_keeps_cleanup_pending(controls):
    connect(controls)

    def failed_delete():
        raise RuntimeError("synthetic deletion failure")

    with pytest.raises(RuntimeError):
        controls.disconnect("alice", "one", failed_delete)
    restarted = Controls(People(controls.store.root))
    assert restarted.status("alice", "one")["state"] == "disconnecting"
    with pytest.raises(StateError):
        restarted.begin("alice", "one")


def test_generation_never_moves_backwards(controls):
    connect(controls)
    attempt = controls.begin("alice", "one")
    controls.stage("alice", "one", attempt, lambda: None)
    with pytest.raises(StateError):
        controls.publish(
            "alice", "one", attempt, lambda: pytest.fail("old generation"), generation=1
        )


def test_shared_borrow_cannot_upgrade_to_publication(controls):
    connect(controls)
    with (
        controls.admitted("alice", "one"),
        pytest.raises(StateError, match="publication_requires_exclusive"),
        controls.operation("alice", "one"),
    ):
        pytest.fail("lock upgraded")
