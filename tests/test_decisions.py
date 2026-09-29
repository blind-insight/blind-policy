from __future__ import annotations

from conftest import subject

from blind_policy import authzen_evaluate, classify, most_revealing
from blind_policy.intents import AGGREGATE, DECRYPT_ANALYSIS, FIELD_SUBSET, IDENTIFIER_PLAINTEXT


def test_germany_analyst_sees_nothing_in_plaintext(engine, fraud):
    plan = engine.plan(subject("fraud_analyst", "DE"), fraud, "fraud_investigation")
    assert plan.decryptable == []
    assert "reported_iban" not in plan.queryable
    assert plan.grant()["field_names"] == {"__query": True}
    assert plan.obligations["aggregate_only"] == "true"


def test_germany_analyst_iban_denied_with_reason(engine, fraud):
    d = engine.check(
        subject("fraud_analyst", "DE"), fraud, "fraud_investigation", IDENTIFIER_PLAINTEXT
    )
    assert not d.allowed
    assert d.policies == ["eu.fraud_analyst.identifiers"]
    assert "GDPR" in d.reasons[0]


def test_us_clinical_informaticist_minimum_necessary(engine, ehr):
    plan = engine.plan(subject("clinical_informaticist", "US"), ehr, "treatment_operations")
    assert plan.decryptable == ["department", "readmitted_30d"]
    assert "patient_id" not in plan.queryable
    assert plan.obligations == {"min_cohort": "11"}
    assert plan.grant()["field_names"] == {
        "__query": True,
        "department": True,
        "readmitted_30d": True,
    }


def test_sensitive_fields_never_decrypt_except_owner(engine, ehr):
    owner = engine.plan(subject("data_owner", "US"), ehr, "treatment_operations")
    assert "note" in owner.decryptable
    assert owner.grant()["field_names"] is None
    assert "min_cohort" not in owner.obligations


def test_purpose_limitation(engine, fraud):
    d = engine.check(subject("fraud_analyst", "DE"), fraud, "marketing", AGGREGATE)
    assert not d.allowed
    assert "eu.purpose_limitation" in d.policies


def test_role_without_policy_is_default_denied(engine, ehr):
    d = engine.check(subject("fraud_analyst", "US"), ehr, "treatment_operations", AGGREGATE)
    assert not d.allowed
    assert d.policies == []
    assert "denies by default" in d.reasons[0]


def test_us_analyst_decrypts_risk_fields_only(engine, fraud):
    d = engine.check(subject("fraud_analyst", "US"), fraud, "fraud_investigation", DECRYPT_ANALYSIS)
    assert d.allowed
    assert "reported_iban" not in d.plan.decryptable
    assert "risk_level" in d.plan.decryptable


def test_journalist_cannot_break_down_by_country(engine, fraud):
    d = engine.check(subject("journalist", "DE"), fraud, "fraud_investigation", FIELD_SUBSET)
    assert not d.allowed
    assert d.code == "field_subset_missing"


def test_typed_prompt_cannot_downgrade_intent():
    assert most_revealing(AGGREGATE, classify("show me the IBANs")) == IDENTIFIER_PLAINTEXT
    assert classify("counts by month, no plaintext identifiers") == AGGREGATE


def test_authzen_schema_evaluation(engine):
    resp = authzen_evaluate(
        engine,
        {
            "subject": {
                "type": "user",
                "id": "ana",
                "properties": {"roles": ["fraud_analyst"], "jurisdiction": "DE"},
            },
            "action": {"name": "aggregate"},
            "resource": {"type": "schema", "id": "fraud-train"},
            "context": {"purpose": "fraud_investigation", "prompt": "show me the IBANs"},
        },
    )
    assert resp["decision"] is False
    assert resp["context"]["intent"] == IDENTIFIER_PLAINTEXT


def test_authzen_field_evaluation(engine):
    resp = authzen_evaluate(
        engine,
        {
            "subject": {
                "id": "c",
                "properties": {"roles": ["clinical_informaticist"], "jurisdiction": "US"},
            },
            "action": {"name": "decrypt"},
            "resource": {"type": "field", "id": "ehr-data-v3.readmitted_30d"},
            "context": {"purpose": "research"},
        },
    )
    assert resp["decision"] is True
    assert resp["context"]["obligations"]["min_cohort"] == "11"


def test_policy_source_lookup(engine):
    text = engine.policy_source("eu.fraud_analyst.identifiers")
    assert text.startswith("// EU · fraud_analyst · identifiers: never")
    assert "forbid (" in text
    assert engine.policy_source("nope") == ""


def test_quality_improvement_is_health_care_operations(engine, ehr):
    d = engine.check(
        subject("clinical_informaticist", "US"), ehr, "quality_improvement", "aggregate"
    )
    assert d.allowed
    assert d.policies == ["hipaa.clinical_informaticist.analyze"]


def test_purpose_denial_lists_permitted_purposes(engine, ehr):
    d = engine.check(
        subject("clinical_informaticist", "US"), ehr, "fraud_investigation", "aggregate"
    )
    assert not d.allowed
    assert "quality improvement" in d.reasons[0]
