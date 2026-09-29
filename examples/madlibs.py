"""Interactive madlibs: "I am a(n) ___ asking about ___ from ___ for ___."

Usage::

    python examples/madlibs.py fraud_analyst "show me the IBANs" DE fraud_investigation
    python examples/madlibs.py clinical_analyst "readmission by department" US \\
        treatment_operations --schema ehr-data-v3
"""

from __future__ import annotations

import argparse
import json

from blind_policy import PolicyEngine, Subject, classify, find_schema


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("role")
    p.add_argument("question")
    p.add_argument("jurisdiction")
    p.add_argument("purpose")
    p.add_argument("--schema", default="fraud")
    a = p.parse_args()

    engine = PolicyEngine.bundled()
    schema = find_schema(a.schema)
    intent = classify(a.question)
    who = Subject("audience-member", [a.role], a.jurisdiction)
    decision = engine.check(who, schema, a.purpose, intent)

    print(f'I am a(n) {a.role} asking about "{a.question}" from {a.jurisdiction} for {a.purpose}.')
    print(f"  intent     {intent}")
    print(f"  decision   {'ALLOW' if decision.allowed else 'DENY'} ({decision.code})")
    print(f"  because    {'; '.join(decision.reasons)}")
    print(f"  policies   {', '.join(decision.policies) or '(none: default deny)'}")
    if decision.allowed:
        print(f"  obligations {json.dumps(decision.obligations)}")
        print(f"  grant      {json.dumps(decision.plan.grant()['field_names'])}")


if __name__ == "__main__":
    main()
