from __future__ import annotations

import pytest

from blind_policy import PolicyEngine, Subject, find_schema


@pytest.fixture(scope="session")
def engine() -> PolicyEngine:
    return PolicyEngine.bundled()


@pytest.fixture(scope="session")
def fraud():
    return find_schema("fraud")


@pytest.fixture(scope="session")
def ehr():
    return find_schema("ehr-data-v3")


def subject(role: str, jurisdiction: str) -> Subject:
    return Subject(user="u1", roles=[role], jurisdiction=jurisdiction)
