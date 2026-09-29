"""Plain data types: who is asking, and what the data looks like.

Nothing here knows about Cedar. ``engine.py`` turns these into Cedar entities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Field sensitivity tags. Policies reason about these, never about raw names alone.
IDENTIFIER = "identifier"  # points at one person or account (IBAN, patient_id)
QUASI = "quasi"  # re-identifying in combination (country, age, visit day)
SENSITIVE = "sensitive"  # special-category content (diagnosis, free-text notes)
ANALYSIS = "analysis"  # metrics that are safe to aggregate (risk_level, billed_amount)

SENSITIVITIES = (IDENTIFIER, QUASI, SENSITIVE, ANALYSIS)
DOMAINS = ("finance", "health", "general")


@dataclass(frozen=True)
class Subject:
    """The human or agent asking. ``jurisdiction`` is where they sit (DE, EU, UK, US, GLOBAL)."""

    user: str
    roles: tuple[str, ...]
    jurisdiction: str

    def __init__(self, user: str, roles: list[str] | tuple[str, ...], jurisdiction: str):
        object.__setattr__(self, "user", user)
        object.__setattr__(self, "roles", tuple(roles))
        object.__setattr__(self, "jurisdiction", jurisdiction.upper())


@dataclass(frozen=True)
class FieldSpec:
    name: str
    sensitivity: str

    def __post_init__(self) -> None:
        if self.sensitivity not in SENSITIVITIES:
            raise ValueError(
                f"field {self.name!r}: sensitivity must be one of {SENSITIVITIES}, "
                f"got {self.sensitivity!r}"
            )


@dataclass(frozen=True)
class SchemaSpec:
    """A Blind Insight schema plus the sensitivity tag of every field."""

    name: str
    domain: str
    fields: tuple[FieldSpec, ...]
    slugs: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if self.domain not in DOMAINS:
            raise ValueError(f"schema {self.name!r}: domain must be one of {DOMAINS}")

    @property
    def field_names(self) -> list[str]:
        return [f.name for f in self.fields]

    def names_with(self, *sensitivities: str) -> list[str]:
        return [f.name for f in self.fields if f.sensitivity in sensitivities]

    def matches(self, slug: str) -> bool:
        slug = (slug or "").strip().lower()
        return bool(slug) and (slug == self.name or slug in self.slugs)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SchemaSpec:
        fields = tuple(
            FieldSpec(name=str(name), sensitivity=str(tag))
            for name, tag in (data.get("fields") or {}).items()
        )
        if not fields:
            raise ValueError(f"schema {data.get('name')!r} declares no fields")
        return cls(
            name=str(data["name"]),
            domain=str(data.get("domain") or "general"),
            fields=fields,
            slugs=tuple(str(s).lower() for s in data.get("slugs") or ()),
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> SchemaSpec:
        return cls.from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
