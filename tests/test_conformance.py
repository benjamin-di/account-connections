from pathlib import Path

import pytest

from account_connections.admission import AdmissionService
from account_connections.controls import Controls
from account_connections.people import People, Policy
from account_connections.testing import ConnectionConformance, Harness


def setup(root: Path) -> Harness:
    people = People(root / "authority")
    controls = Controls(people)
    policy = Policy("1", frozenset({"cart", "orders"}))
    return Harness(
        people,
        controls,
        AdmissionService(people, controls, b"synthetic-test-key" * 2),
        policy,
        "example",
        lambda: setup(root),
    )


@pytest.fixture
def connection_factory():
    return setup


class TestConformance(ConnectionConformance):
    pass
