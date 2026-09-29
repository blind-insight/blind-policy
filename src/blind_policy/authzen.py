"""OpenID AuthZEN Authorization API adapter (evaluation endpoint shape).

Request::

    {"subject":  {"type": "user", "id": "ana",
                  "properties": {"roles": ["fraud_analyst"], "jurisdiction": "DE"}},
     "action":   {"name": "identifier_plaintext"},
     "resource": {"type": "schema", "id": "fraud"},
     "context":  {"purpose": "fraud_investigation", "prompt": "show me the IBANs"}}

``action.name`` is an intent (aggregate, field_subset, decrypt_analysis,
identifier_plaintext) for a whole schema, or ``query_aggregate`` / ``decrypt``
for a single field (``resource.type == "field"``, ``resource.id == "schema.field"``).
"""

from __future__ import annotations

from typing import Any

from .engine import PolicyEngine, find_schema
from .intents import INTENTS, classify, most_revealing
from .model import SchemaSpec, Subject


def _subject(raw: dict[str, Any]) -> Subject:
    props = raw.get("properties") or {}
    return Subject(
        user=str(raw.get("id") or "anonymous"),
        roles=[str(r) for r in props.get("roles") or []],
        jurisdiction=str(props.get("jurisdiction") or "GLOBAL"),
    )


def evaluate(
    engine: PolicyEngine,
    request: dict[str, Any],
    schemas: list[SchemaSpec] | None = None,
) -> dict[str, Any]:
    subject = _subject(request.get("subject") or {})
    action = str((request.get("action") or {}).get("name") or "")
    resource = request.get("resource") or {}
    context = request.get("context") or {}
    purpose = str(context.get("purpose") or "")
    rtype = str(resource.get("type") or "schema")
    rid = str(resource.get("id") or "")

    schema_slug, _, field_name = rid.partition(".") if rtype == "field" else (rid, "", "")
    schema = find_schema(schema_slug, schemas)
    if schema is None:
        return {
            "decision": False,
            "context": {"reason_admin": {"en": f"Unknown or unclassified schema {schema_slug!r}"}},
        }

    if rtype == "field":
        if field_name not in schema.field_names or action not in ("query_aggregate", "decrypt"):
            return {
                "decision": False,
                "context": {"reason_admin": {"en": "Unknown field or action"}},
            }
        plan = engine.plan(subject, schema, purpose)
        d = plan.decisions[(field_name, action)]
        return {
            "decision": d.allowed,
            "context": {
                "reason_admin": {"en": "; ".join(d.reasons)},
                "policies": [p.id for p in d.policies],
                "obligations": plan.obligations if d.allowed else {},
            },
        }

    intent = most_revealing(
        action if action in INTENTS else "",
        classify(str(context.get("prompt") or "")),
    )
    return engine.check(subject, schema, purpose, intent).to_authzen()
