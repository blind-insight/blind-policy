"""Evaluate Cedar policies for every field of a schema and explain the result."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import cedarpy

from .compile import GENERATED_MARKER, compile_file
from .model import IDENTIFIER, SchemaSpec, Subject

ACTIONS = ("query_aggregate", "decrypt")
DEFAULT_DENY = "No policy grants this (Cedar denies by default)"


def _bundled(*parts: str) -> Path:
    return Path(str(resources.files("blind_policy").joinpath("bundled", *parts)))


def cedar_schema() -> str:
    return resources.files("blind_policy").joinpath("bi.cedarschema").read_text(encoding="utf-8")


def bundled_policy_dir() -> Path:
    return _bundled("policies")


def bundled_schemas() -> list[SchemaSpec]:
    return [SchemaSpec.from_yaml(p) for p in sorted(_bundled("fields").glob("*.yaml"))]


def find_schema(slug: str, schemas: list[SchemaSpec] | None = None) -> SchemaSpec | None:
    for spec in schemas if schemas is not None else bundled_schemas():
        if spec.matches(slug):
            return spec
    return None


@dataclass(frozen=True)
class PolicyNote:
    """What one Cedar policy contributed: its id, effect, reason, and obligations."""

    id: str
    effect: str
    regime: str
    reason: str
    obligations: dict[str, str]


@dataclass(frozen=True)
class FieldDecision:
    field: str
    action: str
    allowed: bool
    policies: tuple[PolicyNote, ...]

    @property
    def reasons(self) -> list[str]:
        if not self.policies:
            return [DEFAULT_DENY]
        return [p.reason for p in self.policies]


@dataclass
class FieldPlan:
    """Per-field outcome for one subject, schema, and purpose."""

    subject: Subject
    schema: SchemaSpec
    purpose: str
    decisions: dict[tuple[str, str], FieldDecision] = field(default_factory=dict)

    def allowed(self, action: str) -> list[str]:
        return [name for name in self.schema.field_names if self.decisions[(name, action)].allowed]

    @property
    def queryable(self) -> list[str]:
        return self.allowed("query_aggregate")

    @property
    def decryptable(self) -> list[str]:
        return self.allowed("decrypt")

    @property
    def visible(self) -> list[str]:
        """Fields an agent may even learn exist (for describe_schema)."""
        seen = set(self.queryable) | set(self.decryptable)
        return [name for name in self.schema.field_names if name in seen]

    @property
    def obligations(self) -> dict[str, str]:
        """Obligations from every permit that granted something. min_cohort: strictest wins."""
        merged: dict[str, str] = {}
        for decision in self.decisions.values():
            if not decision.allowed:
                continue
            for note in decision.policies:
                for key, value in note.obligations.items():
                    if key == "min_cohort" and key in merged:
                        merged[key] = str(max(int(merged[key]), int(value)))
                    else:
                        merged[key] = value
        if not self.decryptable:
            merged["aggregate_only"] = "true"
        return merged

    @property
    def policy_ids(self) -> list[str]:
        ids = {note.id for d in self.decisions.values() for note in d.policies}
        return sorted(ids)

    def denied(self, action: str) -> dict[str, list[str]]:
        return {
            name: self.decisions[(name, action)].reasons
            for name in self.schema.field_names
            if not self.decisions[(name, action)].allowed
        }

    def grant(self) -> dict[str, Any] | None:
        from .grants import to_grant

        return to_grant(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": {
                "user": self.subject.user,
                "roles": list(self.subject.roles),
                "jurisdiction": self.subject.jurisdiction,
            },
            "schema": self.schema.name,
            "purpose": self.purpose,
            "queryable": self.queryable,
            "decryptable": self.decryptable,
            "identifiers": self.schema.names_with(IDENTIFIER),
            "obligations": self.obligations,
            "policies": self.policy_ids,
            "grant": self.grant(),
        }


class PolicyEngine:
    """Holds a Cedar policy set and answers "what may this subject read?"."""

    def __init__(self, cedar_text: str, *, validate: bool = True):
        self.cedar_text = cedar_text
        self.schema_text = cedar_schema()
        if validate:
            result = cedarpy.validate_policies(cedar_text, self.schema_text)
            if not result.validation_passed:
                errors = "; ".join(str(e) for e in result.errors)
                raise ValueError(f"Cedar policies failed schema validation: {errors}")
        parsed = json.loads(cedarpy.policies_to_json_str(cedar_text))
        self._notes: dict[str, PolicyNote] = {}
        for internal_id, policy in parsed.get("staticPolicies", {}).items():
            ann = policy.get("annotations") or {}
            self._notes[internal_id] = PolicyNote(
                id=ann.get("id", internal_id),
                effect=policy.get("effect", ""),
                regime=ann.get("regime", ""),
                reason=ann.get("reason", ann.get("id", internal_id)),
                obligations={
                    key[len("obligation_") :]: value
                    for key, value in ann.items()
                    if key.startswith("obligation_")
                },
            )
        # Source text per @id, for showing people the exact rule that decided.
        self._sources: dict[str, str] = {}
        for block in re.split(r"\n\s*\n", cedar_text):
            match = re.search(r'@id\("([^"]+)"\)', block)
            if match:
                self._sources[match.group(1)] = block.strip()

    def policy_source(self, policy_id: str) -> str:
        """The Cedar text of one policy (with its leading comment), by ``@id``."""
        return self._sources.get(policy_id, "")

    @classmethod
    def from_dir(cls, directory: str | Path) -> PolicyEngine:
        """Load every ``*.yaml`` regime (compiled fresh) and hand-written ``*.cedar`` file."""
        directory = Path(directory)
        parts: list[str] = []
        for yml in sorted(directory.glob("*.yaml")):
            parts.append(compile_file(yml))
        for ced in sorted(directory.glob("*.cedar")):
            text = ced.read_text(encoding="utf-8")
            if text.startswith(GENERATED_MARKER):
                continue  # compiled output; the YAML above is the source of truth
            parts.append(text)
        if not parts:
            raise ValueError(f"no policies found in {directory}")
        return cls("\n\n".join(parts))

    @classmethod
    def bundled(cls) -> PolicyEngine:
        return cls.from_dir(bundled_policy_dir())

    def _entities(self, subject: Subject, schema: SchemaSpec) -> list[dict[str, Any]]:
        entities: list[dict[str, Any]] = [
            {"uid": {"type": "BI::Role", "id": role}, "attrs": {}, "parents": []}
            for role in subject.roles
        ]
        entities.append(
            {
                "uid": {"type": "BI::User", "id": subject.user},
                "attrs": {"jurisdiction": subject.jurisdiction},
                "parents": [{"type": "BI::Role", "id": role} for role in subject.roles],
            }
        )
        for spec in schema.fields:
            entities.append(
                {
                    "uid": {"type": "BI::Field", "id": f"{schema.name}.{spec.name}"},
                    "attrs": {
                        "name": spec.name,
                        "schema": schema.name,
                        "domain": schema.domain,
                        "sensitivity": spec.sensitivity,
                    },
                    "parents": [],
                }
            )
        return entities

    def plan(self, subject: Subject, schema: SchemaSpec, purpose: str) -> FieldPlan:
        """Decide query and decrypt for every field in one batched Cedar call."""
        keys = [(spec.name, action) for spec in schema.fields for action in ACTIONS]
        requests = [
            {
                "principal": f'BI::User::"{subject.user}"',
                "action": f'BI::Action::"{action}"',
                "resource": f'BI::Field::"{schema.name}.{name}"',
                "context": {"purpose": purpose},
            }
            for name, action in keys
        ]
        results = cedarpy.is_authorized_batch(
            requests, self.cedar_text, self._entities(subject, schema), schema=self.schema_text
        )
        plan = FieldPlan(subject=subject, schema=schema, purpose=purpose)
        for (name, action), result in zip(keys, results, strict=False):
            errors = list(result.diagnostics.errors)
            if errors:
                raise RuntimeError(f"Cedar evaluation error for {name}/{action}: {errors}")
            notes = tuple(
                self._notes[pid] for pid in result.diagnostics.reasons if pid in self._notes
            )
            plan.decisions[(name, action)] = FieldDecision(
                field=name, action=action, allowed=result.allowed, policies=notes
            )
        return plan

    def check(self, subject: Subject, schema: SchemaSpec, purpose: str, intent: str):
        """Plan the fields, then decide whether this kind of question can be answered."""
        from .intents import decide

        return decide(self.plan(subject, schema, purpose), intent)
