"""Command line: ``blind-policy plan | check | compile``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .compile import compile_dir, compile_file
from .engine import PolicyEngine, bundled_policy_dir, bundled_schemas, find_schema
from .intents import INTENTS, classify, most_revealing
from .model import SchemaSpec, Subject


def _engine(args: argparse.Namespace) -> PolicyEngine:
    return PolicyEngine.from_dir(args.policies) if args.policies else PolicyEngine.bundled()


def _schema(args: argparse.Namespace) -> SchemaSpec:
    if Path(args.schema).is_file():
        return SchemaSpec.from_yaml(args.schema)
    spec = find_schema(args.schema)
    if spec is None:
        names = ", ".join(s.name for s in bundled_schemas())
        raise SystemExit(f"unknown schema {args.schema!r} (bundled: {names}, or pass a YAML path)")
    return spec


def _subject(args: argparse.Namespace) -> Subject:
    return Subject(user=args.user, roles=args.role, jurisdiction=args.jurisdiction)


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--role", action="append", required=True, help="repeatable")
    p.add_argument("--jurisdiction", required=True, help="DE, EU, UK, US, GLOBAL")
    p.add_argument("--schema", required=True, help="bundled schema name/slug or YAML path")
    p.add_argument("--purpose", required=True)
    p.add_argument("--user", default="demo-user")
    p.add_argument("--policies", help="policy directory (default: bundled)")


def cmd_plan(args: argparse.Namespace) -> int:
    plan = _engine(args).plan(_subject(args), _schema(args), args.purpose)
    print(json.dumps(plan.as_dict(), indent=2))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    intent = most_revealing(args.intent or "", classify(args.prompt or ""))
    decision = _engine(args).check(_subject(args), _schema(args), args.purpose, intent)
    print(json.dumps(decision.to_authzen(), indent=2))
    return 0 if decision.allowed else 1


def cmd_compile(args: argparse.Namespace) -> int:
    target = Path(args.path or bundled_policy_dir())
    if target.is_file():
        sys.stdout.write(compile_file(target))
        return 0
    results = compile_dir(target, write=args.write)
    for path, text in results.items():
        if args.write:
            print(f"wrote {path}")
        else:
            sys.stdout.write(text + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blind-policy", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("plan", help="which fields may be queried / decrypted, and the Grant")
    _common(p)
    p.set_defaults(func=cmd_plan)

    c = sub.add_parser("check", help="may this question be answered? (AuthZEN response)")
    _common(c)
    c.add_argument("--intent", choices=INTENTS)
    c.add_argument("--prompt", help="typed question; the more revealing of intent/prompt wins")
    c.set_defaults(func=cmd_check)

    k = sub.add_parser("compile", help="print or write the Cedar compiled from YAML regimes")
    k.add_argument("path", nargs="?", help="a regime YAML or a directory (default: bundled)")
    k.add_argument("--write", action="store_true", help="write <name>.cedar next to each YAML")
    k.set_defaults(func=cmd_compile)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
