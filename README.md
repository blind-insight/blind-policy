# blind-policy

**Decide what an AI agent may read, then make the answer stick with encryption keys.**

Agent stacks already decide _whether_ a call runs: identity providers, MCP gateways, policy engines. Almost none decide _what the call can read_ once it reaches the data. `blind-policy` connects the two:

```
who is asking  +  why  +  under which regime
        │
        ▼
  YAML regime file  ──compile──▶  Cedar policies  ──evaluate──▶  per-field plan
                                                                     │
                                                                     ▼
                                              Blind Insight Grant: which keys the agent's proxy receives
```

- **Readable policies.** Write rules the way a compliance memo reads (see below). They compile to [Cedar](https://www.cedarpolicy.com), the open-source policy language behind Amazon Verified Permissions and Bedrock AgentCore Policy.
- **Field-level answers.** For every field of a schema: may the agent query it (encrypted count / average / filter)? May it decrypt it?
- **Reasons and obligations.** Every decision names the policies that produced it, cites the regime, and carries obligations such as `min_cohort: 11`.
- **Keys, not promises.** The plan compiles to the shape of a [Blind Insight](https://blindinsight.com) `Grant`. Decrypt keys the Grant doesn't list never reach the agent's proxy, so a prompt-injected agent can't read those fields however it's instructed.
- **Standard interface.** Responses follow the [OpenID AuthZEN](https://openid.net/specs/authorization-api-1_0.html) evaluation shape, so you can put this behind any AuthZEN-speaking gateway.
- **Runs in-process.** `pip install`, no server. Cedar evaluation is via [`cedarpy`](https://github.com/k9securityio/cedar-py).

## Install

```bash
pip install -e .          # from a checkout (PyPI release to follow)
blind-policy --help
```

## A policy, as you'd put it on a slide

```yaml
# EU  →  GDPR Art. 5(1)(c) · DORA Art. 9(2)
regime: EU
cite: GDPR Art. 5(1)(c) data minimisation · DORA Art. 9(2)
applies_to:
  jurisdictions: [DE, EU, UK]
purposes:
  [fraud_investigation, regulatory_reporting, research, treatment_operations]
purpose_cite: GDPR Art. 5(1)(b) purpose limitation
roles:
  fraud_analyst:
    analyze: all fields
    decrypt: none # data minimisation
    identifiers: never
```

```yaml
# US  →  HIPAA §164.502(b) minimum necessary
regime: HIPAA
applies_to:
  jurisdictions: [US]
  domains: [health]
obligations:
  min_cohort: 11
roles:
  clinical_informaticist:
    analyze: all fields
    decrypt: department, readmitted_30d
    identifiers: never # §164.514(b) Safe Harbor
```

`analyze` hands out the query key (encrypted aggregates). `decrypt` hands out per-field data keys. `identifiers: never` compiles to an explicit Cedar `forbid`, which overrides any permit. Here is the compiled Cedar for the EU analyst:

```cedar
@id("eu.fraud_analyst.identifiers")
@regime("EU")
@reason("GDPR Art. 5(1)(c) data minimisation · DORA Art. 9(2): identifiers never leave the proxy for this role")
forbid (
  principal in BI::Role::"fraud_analyst",
  action in [BI::Action::"query_aggregate", BI::Action::"decrypt"],
  resource is BI::Field
) when {
  ["DE", "EU", "UK"].contains(principal.jurisdiction) &&
  resource.sensitivity == "identifier"
};
```

Bundled regimes live in [`src/blind_policy/bundled/policies/`](src/blind_policy/bundled/policies/): `eu`, `us-health` (HIPAA), `us-finance`, `global`, plus a hand-written `baseline.cedar`. The `.cedar` files are generated and committed, so you can read exactly what runs; edit the YAML and run `blind-policy compile --write`.

> These regime files are worked examples of how to encode rules. They are not legal advice. The small-cell floor of 11 follows the CMS cell-size suppression convention and is a configurable default, not a HIPAA requirement.

## Try it

```bash
# A German fraud analyst asks for IBANs → denied, with the policy and citation
blind-policy check --role fraud_analyst --jurisdiction DE --schema fraud \
  --purpose fraud_investigation --prompt "show me the IBANs"

# A US clinical informaticist: what may they read in the EHR schema, and what Grant does that become?
blind-policy plan --role clinical_informaticist --jurisdiction US --schema ehr-data-v3 \
  --purpose treatment_operations
```

```python
from blind_policy import PolicyEngine, Subject, find_schema

engine = PolicyEngine.bundled()  # or PolicyEngine.from_dir("my-policies/")
analyst = Subject("ana", roles=["clinical_informaticist"], jurisdiction="US")
plan = engine.plan(analyst, find_schema("ehr-data-v3"), purpose="treatment_operations")

plan.queryable  # fields the agent may count / average / filter
plan.decryptable  # ['department', 'readmitted_30d']
plan.obligations  # {'min_cohort': '11'}
plan.grant()  # {'field_names': {'__query': True, 'department': True, 'readmitted_30d': True}, ...}

decision = engine.check(
    analyst, find_schema("ehr-data-v3"), "treatment_operations", "identifier_plaintext"
)
decision.allowed, decision.policies, decision.reasons
decision.to_authzen()
```

## Concepts

| Concept             | In blind-policy                                                                    | In Blind Insight                                        |
| ------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Who is asking       | `Subject(user, roles, jurisdiction)`                                               | User, Team membership                                   |
| Why                 | `purpose` (e.g. `fraud_investigation`, `treatment_operations`)                     | Request context                                         |
| Which regime        | YAML `applies_to` (jurisdictions, data domains)                                    | n/a                                                     |
| What the data is    | `SchemaSpec`: every field tagged `identifier` / `quasi` / `sensitive` / `analysis` | Schema                                                  |
| May query a field   | Cedar action `query_aggregate`                                                     | `__query` key (encrypted count / avg / filter)          |
| May decrypt a field | Cedar action `decrypt`                                                             | per-field data key                                      |
| The outcome         | `FieldPlan.grant()`                                                                | `Grant.field_names` → key delivery to the agent's proxy |

Field tags for the demo schemas (`fraud`, `customer_graph`, `ehr-data-v3`) are in [`bundled/fields/`](src/blind_policy/bundled/fields/). Tag your own schema the same way:

```yaml
name: claims
domain: health # finance | health | general
fields:
  member_id: identifier
  zip3: quasi
  diagnosis_code: sensitive
  paid_amount: analysis
```

### Intents

`check()` answers one of four kinds of question, from least to most revealing: `aggregate`, `field_subset` (breakdowns by quasi-identifiers), `decrypt_analysis`, `identifier_plaintext`. When a request carries both a picked intent and typed text, the more revealing one wins, so typing "show me the IBANs" under an innocuous intent is still caught. The keyword classifier (`classify`) is deliberately simple; swap in your own.

### What is enforced where

Be precise about this when you build on it:

| Control                        | Enforced by                                                                                                                        |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Decrypt a field                | **Cryptography.** Only the field keys listed in the Grant reach the agent's proxy.                                                 |
| Query a field                  | **The policy gate.** The `__query` key covers all fields of a schema, so which fields may be queried is checked before each query. |
| `min_cohort`, `aggregate_only` | **The caller.** Returned as obligations; your orchestrator (or proxy) must apply them.                                             |

## With an AI agent

Put the engine in front of the agent's data tools. With Blind Insight's BlindLLM tools (`list_schemas`, `describe_schema`, `query_aggregate`, `suggest_ml_approach`):

- `describe_schema` → show the model only `plan.visible` fields.
- `query_aggregate` → refuse filters on fields outside `plan.queryable`; apply `min_cohort`.
- Key delivery → mint the Grant from `plan.grant()` so decryption is bounded by keys, not by the prompt.

See [`examples/POC.md`](examples/POC.md) for an end-to-end proof of concept, and [`examples/madlibs.py`](examples/madlibs.py) for the interactive "I am a(n) ___ asking about ___ from ___ for ___" demo.

## Develop

```bash
uv sync
uv run pytest
uv run pre-commit run -a
```

`tests/test_parity.py` replays the persona table from the Blind Insight local demo console through the Cedar policies. Any difference is either a bug or listed in `examples/personas.yaml` with a reason.

## License

MIT.
