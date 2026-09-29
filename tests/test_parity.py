"""Replay the old console persona table through the Cedar policies."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from conftest import subject

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = yaml.safe_load((ROOT / "examples" / "personas.yaml").read_text(encoding="utf-8"))


def tier(plan) -> str:
    grant = plan.grant()
    if grant and grant["field_names"] is None:
        return "analyze_decrypt_all"
    if plan.decryptable:
        return "analyze_decrypt_some"
    non_identifiers = [f.name for f in plan.schema.fields if f.sensitivity != "identifier"]
    if set(plan.queryable) >= set(non_identifiers):
        return "analyze_all_no_decrypt"
    return "analyze_some_no_decrypt"


ROWS = [
    (job, loc, expected)
    for job, by_loc in FIXTURE["tiers"].items()
    for loc, expected in by_loc.items()
]


@pytest.mark.parametrize(("job", "loc", "expected"), ROWS)
def test_persona_tier_parity(engine, fraud, job, loc, expected):
    plan = engine.plan(subject(job, FIXTURE["jurisdictions"][loc]), fraud, "fraud_investigation")
    got = tier(plan)
    if f"{job}/{loc}" in FIXTURE["intentional_differences"]:
        assert got != expected, f"{job}/{loc} was marked as an intentional difference"
    else:
        assert got == expected


def test_thirty_rows():
    assert len(ROWS) == 30
