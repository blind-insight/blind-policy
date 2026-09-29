"""What kind of question is being asked, and can this field plan answer it?

Four intents, from least to most revealing:

    aggregate            counts, averages, rates over encrypted data
    field_subset         breakdowns by quasi-identifiers (country, age, sex)
    decrypt_analysis     plaintext of non-identifying fields
    identifier_plaintext plaintext that points at a person or account

When a question arrives both as a picked intent and as typed text, the most
revealing of the two wins, so typing "show me the IBANs" under an innocuous
picked intent cannot slip through.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .engine import DEFAULT_DENY, FieldPlan
from .model import IDENTIFIER, QUASI

AGGREGATE = "aggregate"
FIELD_SUBSET = "field_subset"
DECRYPT_ANALYSIS = "decrypt_analysis"
IDENTIFIER_PLAINTEXT = "identifier_plaintext"

INTENTS = (AGGREGATE, FIELD_SUBSET, DECRYPT_ANALYSIS, IDENTIFIER_PLAINTEXT)

_IDENTIFIER_HINTS = (
    "iban",
    "customer id",
    "customer_id",
    "customer ids",
    "report_id",
    "patient id",
    "patient_id",
    "patient ids",
    "account number",
    "plaintext name",
    "names of",
    "show me the people",
    "who is",
    "identify",
    "deanonym",
    "re-identif",
    "reidentif",
)
_DECRYPT_HINTS = (
    "decrypt",
    "plaintext",
    "cleartext",
    "in the clear",
    "unencrypt",
    "raw rows",
    "raw records",
    "sample rows",
    "show rows",
    "show records",
)
_SUBSET_HINTS = (
    "jurisdiction",
    "country",
    "countries",
    "germany",
    "home_country",
    "ip_country",
    "by age",
    "age group",
    "by sex",
    "by gender",
    "zip",
    "postcode",
)


# "no plaintext identifiers" is a request to stay encrypted, not a request for plaintext.
_NEGATED = re.compile(
    r"\b(?:no|without|not|never|excluding)\s+(?:any\s+)?"
    r"(?:plaintext|cleartext|decrypt\w*|identif\w*|ibans?|names?|pii|phi)(?:\s+\w+)?"
)


def classify(text: str) -> str:
    """Keyword classifier for free text. Conservative: when in doubt, the more revealing intent."""
    low = _NEGATED.sub(" ", (text or "").lower())
    if any(h in low for h in _IDENTIFIER_HINTS):
        return IDENTIFIER_PLAINTEXT
    if any(h in low for h in _DECRYPT_HINTS):
        return DECRYPT_ANALYSIS
    if any(h in low for h in _SUBSET_HINTS):
        return FIELD_SUBSET
    return AGGREGATE


def most_revealing(*intents: str) -> str:
    known = [i for i in intents if i in INTENTS]
    if not known:
        return AGGREGATE
    return max(known, key=INTENTS.index)


@dataclass
class Decision:
    allowed: bool
    intent: str
    code: str
    message: str
    plan: FieldPlan
    reasons: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)

    @property
    def obligations(self) -> dict[str, str]:
        return self.plan.obligations if self.allowed else {}

    def to_authzen(self) -> dict[str, Any]:
        """OpenID AuthZEN-shaped response: a boolean decision plus free-form context."""
        return {
            "decision": self.allowed,
            "context": {
                "reason_user": {"en": self.message},
                "reason_admin": {"en": "; ".join(self.reasons)},
                "intent": self.intent,
                "code": self.code,
                "policies": self.policies,
                "obligations": self.obligations,
                "grant": self.plan.grant() if self.allowed else None,
            },
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "intent": self.intent,
            "code": self.code,
            "message": self.message,
            "reasons": self.reasons,
            "policies": self.policies,
            "obligations": self.obligations,
            "plan": self.plan.as_dict(),
        }


def _explain(plan: FieldPlan, action: str, fields: list[str]) -> tuple[list[str], list[str]]:
    """Collect the forbid reasons (or default deny) behind denied fields."""
    reasons: list[str] = []
    ids: list[str] = []
    for name in fields:
        d = plan.decisions[(name, action)]
        if d.allowed:
            continue
        for note in d.policies:
            if note.reason not in reasons:
                reasons.append(note.reason)
            if note.id not in ids:
                ids.append(note.id)
    if not reasons:
        reasons.append(DEFAULT_DENY)
    return reasons, ids


def _granting(plan: FieldPlan, action: str, fields: list[str]) -> tuple[list[str], list[str]]:
    reasons: list[str] = []
    ids: list[str] = []
    for name in fields:
        d = plan.decisions[(name, action)]
        if not d.allowed:
            continue
        for note in d.policies:
            if note.reason not in reasons:
                reasons.append(note.reason)
            if note.id not in ids:
                ids.append(note.id)
    return reasons, ids


def decide(plan: FieldPlan, intent: str) -> Decision:
    schema = plan.schema
    identifiers = schema.names_with(IDENTIFIER)
    non_identifiers = [n for n in schema.field_names if n not in identifiers]
    quasi = schema.names_with(QUASI)

    if intent == IDENTIFIER_PLAINTEXT:
        action, candidates = "decrypt", identifiers
        ok = bool(identifiers) and all(n in plan.decryptable for n in identifiers)
        code_ok, code_no = "identifier_decrypt_allowed", "identifier_plaintext_blocked"
        msg_no = (
            "This asks for plaintext that could identify a person or account, which this "
            "role may not see here. Ask for encrypted aggregates instead."
        )
    elif intent == DECRYPT_ANALYSIS:
        action, candidates = "decrypt", non_identifiers
        ok = any(n in plan.decryptable for n in non_identifiers)
        code_ok, code_no = "decrypt_allowed", "decrypt_not_in_grant"
        msg_no = (
            "This role holds no decrypt keys for these fields here. Ask for an encrypted "
            "aggregate (counts, averages, rates) instead."
        )
    elif intent == FIELD_SUBSET:
        action, candidates = "query_aggregate", quasi
        ok = any(n in plan.queryable for n in quasi)
        code_ok, code_no = "field_subset_ok", "field_subset_missing"
        msg_no = (
            "This role may not break results down by re-identifying fields "
            "(country, age, dates). Ask for totals or rates instead."
        )
    else:
        intent = AGGREGATE
        action, candidates = "query_aggregate", non_identifiers
        ok = any(n in plan.queryable for n in non_identifiers)
        code_ok, code_no = "aggregate_ok", "no_queryable_fields"
        msg_no = "This role may not query this data for this purpose."

    if ok:
        reasons, ids = _granting(plan, action, candidates)
        allowed_fields = plan.decryptable if action == "decrypt" else plan.queryable
        message = f"Allowed: {action.replace('_', ' ')} on {len(allowed_fields)} field(s)."
        return Decision(True, intent, code_ok, message, plan, reasons, ids)
    reasons, ids = _explain(plan, action, candidates or schema.field_names)
    return Decision(False, intent, code_no, msg_no, plan, reasons, ids)
