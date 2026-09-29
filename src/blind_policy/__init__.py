"""blind-policy: decide what an AI agent may read, and compile it to encryption keys.

Example::

    from blind_policy import PolicyEngine, Subject, find_schema

    engine = PolicyEngine.bundled()
    ana = Subject("ana", ["fraud_analyst"], "DE")
    plan = engine.plan(ana, find_schema("fraud"), "fraud_investigation")
    plan.queryable, plan.decryptable, plan.grant()
"""

from .authzen import evaluate as authzen_evaluate
from .compile import compile_dir, compile_file, compile_regime
from .engine import (
    FieldPlan,
    PolicyEngine,
    bundled_policy_dir,
    bundled_schemas,
    cedar_schema,
    find_schema,
)
from .intents import INTENTS, Decision, classify, most_revealing
from .model import FieldSpec, SchemaSpec, Subject

__all__ = [
    "INTENTS",
    "Decision",
    "FieldPlan",
    "FieldSpec",
    "PolicyEngine",
    "SchemaSpec",
    "Subject",
    "authzen_evaluate",
    "bundled_policy_dir",
    "bundled_schemas",
    "cedar_schema",
    "classify",
    "compile_dir",
    "compile_file",
    "compile_regime",
    "find_schema",
    "most_revealing",
]
__version__ = "0.1.0"
