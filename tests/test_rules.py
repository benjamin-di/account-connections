import pytest

from account_connections import (
    Choice,
    ConnectionError,
    Grant,
    Selection,
    choose,
    leave,
    offer,
    resolve,
    revoke,
)

USE = frozenset({"use"})


def test_offer_never_routes_and_same_scope_preserves_revision():
    selected = Selection(Choice("bob"), "selection")
    grant = offer(None, expected=None, capabilities=USE)
    assert resolve("bob", selected, None).owner == "bob"
    assert offer(grant, expected=grant.revision, capabilities=USE) is grant
    with pytest.raises(ConnectionError, match="account_changed"):
        offer(grant, expected=None, capabilities=USE)


def test_switch_and_no_fallback():
    own = Selection(Choice("bob"), "initial")
    grant = offer(None, expected=None, capabilities=USE)
    choice = Choice("alice", grant.revision)
    shared = choose("bob", own, choice, grant, expected=own.revision)
    assert resolve("bob", shared, grant, capability="use").owner == "alice"
    assert choose("bob", shared, choice, grant, expected=shared.revision) is shared
    with pytest.raises(ConnectionError, match="shared_access_removed"):
        resolve("bob", shared, None)
    back = choose("bob", shared, Choice("bob"), None, expected=shared.revision)
    assert back.revision not in {own.revision, shared.revision}
    again = choose("bob", back, choice, grant, expected=back.revision)
    assert again.revision not in {own.revision, shared.revision, back.revision}
    with pytest.raises(ConnectionError, match="account_changed"):
        choose("bob", again, Choice("bob"), None, expected=shared.revision)


def test_scope_change_regrant_and_capabilities():
    grant = offer(None, expected=None, capabilities=USE)
    selected = Selection(Choice("alice", grant.revision), "chosen")
    with pytest.raises(ConnectionError, match="capability_not_shared"):
        resolve("bob", selected, grant, capability="history")
    changed = offer(grant, expected=grant.revision, capabilities=USE | {"history"})
    with pytest.raises(ConnectionError, match="shared_access_removed"):
        resolve("bob", selected, changed)
    revoke(changed, expected=changed.revision)
    reissued = offer(None, expected=None, capabilities=USE)
    assert reissued.revision not in {grant.revision, changed.revision}
    with pytest.raises(ConnectionError, match="shared_access_removed"):
        resolve("bob", selected, reissued)
    with pytest.raises(ConnectionError, match="shared_access_removed"):
        revoke(reissued, expected=changed.revision)


def test_leave_clears_stale_scope_and_preserves_other_choice():
    selected = Selection(Choice("alice", "old-grant"), "chosen")
    cleared = leave(selected, "alice")
    assert cleared.choice is None and cleared.revision != selected.revision
    with pytest.raises(ConnectionError, match="account_selection_needed"):
        resolve("bob", cleared, None)
    other = Selection(Choice("carol", "other-grant"), "other-choice")
    assert leave(other, "alice") is other


@pytest.mark.parametrize("choice", [None, Choice("bob", "unexpected")])
def test_empty_and_invalid_owned_choice(choice):
    with pytest.raises(ConnectionError, match="account_selection_needed"):
        resolve("bob", Selection(choice, "chosen"), None)


def test_values_are_immutable_and_validated():
    with pytest.raises(ValueError):
        Grant("revision", {"use"})
    with pytest.raises(ValueError):
        Choice("")
    with pytest.raises(ValueError):
        Selection({}, "revision")
