import pytest
from starlette.datastructures import Headers

from account_connections.admission import gateway_person
from account_connections.storage import StateError


@pytest.mark.parametrize(
    "headers",
    [
        Headers(),
        Headers({"x-fleet-person": ""}),
        Headers({"x-fleet-person": "alice,bob"}),
        Headers({"x-fleet-person": "../alice"}),
        Headers(raw=[(b"x-fleet-person", b"alice"), (b"x-fleet-person", b"bob")]),
        {"X-Fleet-Person": "alice", "x-fleet-person": "bob"},
    ],
)
def test_gateway_person_rejects_ambiguous_or_missing_identity(headers):
    with pytest.raises(StateError, match="account_selection_needed"):
        gateway_person(headers, backend_authenticated=True)


def test_gateway_person_requires_verified_backend_boundary():
    headers = Headers({"x-fleet-person": "alice"})
    with pytest.raises(StateError):
        gateway_person(headers, backend_authenticated=False)
    assert gateway_person(headers, backend_authenticated=True) == "alice"
    assert gateway_person({"X-Fleet-Person": "bob"}, backend_authenticated=True) == "bob"
