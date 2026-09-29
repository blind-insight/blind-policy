from __future__ import annotations

import cedarpy
import pytest

from blind_policy import bundled_policy_dir, cedar_schema, compile_dir, compile_regime
from blind_policy.compile import PolicyFileError


def test_committed_cedar_matches_yaml():
    """The .cedar files in the repo are exactly what the YAML compiles to."""
    for path, text in compile_dir(bundled_policy_dir()).items():
        assert path.read_text(encoding="utf-8") == text, (
            f"{path.name} is stale: run compile --write"
        )


def test_all_policies_validate_against_schema():
    d = bundled_policy_dir()
    text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(d.glob("*.cedar")))
    result = cedarpy.validate_policies(text, cedar_schema())
    assert result.validation_passed, [str(e) for e in result.errors]


def test_slide_style_selectors():
    text = compile_regime(
        {
            "regime": "US",
            "roles": {"clinical_analyst": {"analyze": "all fields", "decrypt": "a, b"}},
        }
    )
    assert '["a", "b"].contains(resource.name)' in text
    assert 'resource.sensitivity != "identifier"' in text
    assert '@id("us.clinical_analyst.identifiers")' in text


def test_unknown_obligation_rejected():
    with pytest.raises(PolicyFileError):
        compile_regime({"regime": "X", "obligations": {"mask": 1}, "roles": {"r": {}}})


def test_bad_identifiers_value_rejected():
    with pytest.raises(PolicyFileError):
        compile_regime({"regime": "X", "roles": {"r": {"identifiers": "sometimes"}}})
