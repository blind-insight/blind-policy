"""Turn a field plan into the shape of a Blind Insight ``Grant``.

A Grant hands out keys: ``__query`` lets the holder count, average and filter
over ciphertext; a per-field key lets the holder decrypt that one field.
``field_names=None`` means everything (the data owner). Keys the Grant does
not list are never delivered to the agent's proxy, so a hijacked agent cannot
read those fields no matter what it is told.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import FieldPlan

QUERY_KEY = "__query"


def to_grant(plan: FieldPlan) -> dict[str, Any] | None:
    queryable = plan.queryable
    decryptable = plan.decryptable
    if not queryable and not decryptable:
        return None
    everything = set(plan.schema.field_names)
    if set(decryptable) == everything and set(queryable) == everything:
        field_names = None
    else:
        field_names = {QUERY_KEY: True} if queryable else {}
        field_names.update({name: True for name in decryptable})
    return {
        "schema": plan.schema.name,
        "field_names": field_names,
        "can_decrypt": bool(decryptable),
        "query_fields": queryable,
        "decrypt_fields": decryptable,
        "enforcement": {
            "decrypt_fields": "cryptographic: only these field keys reach the agent's proxy",
            "query_fields": "policy gate: checked before each query; __query covers all fields",
        },
    }
