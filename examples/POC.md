# Build a proof of concept: an agent that can't read what it isn't granted

This walks through wiring an LLM agent to encrypted data so that (1) a policy decides what the agent may read, and (2) encryption keys enforce it. It takes about an afternoon.

## What you need

| Piece                      | What it does                                                                                           | Where                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| Blind Insight sandbox      | Encrypted storage and search. The server only ever sees ciphertext.                                    | Sign up: `<SIGNUP URL — to be confirmed>`                    |
| `blind` CLI + Blind Proxy  | Holds your keys locally; encrypts, decrypts, and turns filters into keyed trapdoors                    | [docs.blindinsight.io](https://docs.blindinsight.io)         |
| `blindllm`                 | Open-source model instructions: system prompt, tool contract, and OpenAI / Anthropic / Gemini adapters | [github.com/blind-insight](https://github.com/blind-insight) |
| `blind-policy` (this repo) | Decides what the agent may read, then compiles that into a Grant                                       | this repo                                                    |

## 1. Load encrypted data

Create a dataset and schema, then upload records with the `blind` CLI. The proxy encrypts each field before it leaves your machine. Follow the quickstart at [docs.blindinsight.io](https://docs.blindinsight.io). Always log in against the host you mean to use, and run `blind schema list` to confirm before uploading.

## 2. Tag your fields

Write a field file for your schema (see `src/blind_policy/bundled/fields/` for examples). Every field is `identifier`, `quasi`, `sensitive` or `analysis`.

## 3. Write your regime file

Start from `src/blind_policy/bundled/policies/eu.yaml` or `us-health.yaml`. Name your roles, say what each may `analyze` and `decrypt`, and list the permitted `purposes`. Compile it, then read the Cedar it produces:

```bash
blind-policy compile my-policies/ --write
blind-policy plan --policies my-policies/ --schema my-fields.yaml \
  --role analyst --jurisdiction DE --purpose research
```

## 4. Put the decision in front of the agent

```python
from blindllm import build_provider          # model instructions + provider adapter
from blind_policy import PolicyEngine, Subject, SchemaSpec, classify

engine = PolicyEngine.from_dir("my-policies/")
schema = SchemaSpec.from_yaml("my-fields.yaml")
user = Subject("ana", roles=["analyst"], jurisdiction="DE")

decision = engine.check(user, schema, purpose="research", intent=classify(question))
if not decision.allowed:
    return decision.message, decision.reasons        # never reaches the model

plan = decision.plan
catalog = {"schemas": [{"slug": schema.name, "fields": plan.visible}]}   # the model only sees these
# ... run the agent loop; before each query_aggregate, check its filter fields are in plan.queryable
```

## 5. Make it cryptographic

`plan.grant()` returns the `field_names` for a Blind Insight Grant, for example `{"__query": true, "department": true}`. Create that Grant for the agent's team, and the agent's proxy receives only those keys. Now even a fully prompt-injected agent can decrypt nothing beyond `department`.

## Questions to ask of any agent stack

1. Who holds the keys to what your agent reads?
2. If your gateway is bypassed, what can the agent read?
3. Can an agent decrypt a field it was never granted?
4. Does your vendor ever hold a key?
5. What does the model provider receive: records or numbers?
