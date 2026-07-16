# Policy enforcement

The audit log tells you whether the data *was* handled correctly. Policy turns
that from an observation into a control: declarative rules that **monitor**
live state and **enforce** them at write time — neleus refuses the write that
would create a violation.

Policies live in `meta/policy.json` and are edited as code (CLI `policy set`,
HTTP `POST /v1/policy`, or the **Policies** view in the console). Violations are
recorded to a tamper-evident event log and can fire a webhook.

## The model

A policy binds a **rule** to a set of **heads**, in a **mode**, at a
**severity**:

```json
{
  "webhook": "http://127.0.0.1:9000/hook",
  "policies": [
    { "id": "clinical-encrypted",
      "rule": { "kind": "require-encryption-at-rest" },
      "mode": "enforce" },
    { "id": "clinical-retention",
      "rule": { "kind": "retention-floor", "min_secs": 220752000 },
      "mode": "enforce", "severity": "required" },
    { "id": "named-agents",
      "heads": ["clinical/*"],
      "rule": { "kind": "require-principal" },
      "mode": "enforce" },
    { "id": "signed-history",
      "heads": ["clinical/*"],
      "rule": { "kind": "require-signed-checkpoints" },
      "mode": "monitor", "severity": "recommended" }
  ]
}
```

- **`heads`** — exact names, a `prefix*` wildcard, or `*`/omitted = all heads.
  Database-global rules (encryption, retention) ignore the selector.
- **`mode`** — `enforce` rejects the offending write (HTTP 403); `monitor`
  allows it but records the violation.
- **`severity`** — `required` (default) or `recommended`; surfaced in reports
  and the console, does not change blocking behavior.
- **`enabled`** — defaults true; set false to park a policy without deleting it.

## Rules

| `kind` | What it checks | Gateable at write time |
|---|---|---|
| `require-tamper-evident-chain` | The head's checkpoint chain verifies | no (continuous) |
| `require-signed-checkpoints` | Every checkpoint on the head is signed | no (continuous) |
| `require-signed-commits` | The head's tip commit carries a signature | no (continuous) |
| `require-encryption-at-rest` | Encryption at rest is enabled (global) | **yes** |
| `retention-floor` (`min_secs`) | Retention floor ≥ `min_secs` (global) | **yes** |
| `require-principal` | The write names an authenticated principal | **yes** |
| `require-provenance` | A run declares a provider or input/retrieved data | **yes** (runs) |

Continuous rules are evaluated by `policy eval` / `POST /v1/policy/evaluate`
against live state. Write-time rules are also enforced inline on `POST
/v1/documents`, `/v1/runs`, and `/v1/commits` at the server boundary. (The
admin CLI is an escape hatch and is not gated — the server is the enforcement
point for agents.)

## Continuous monitoring

```bash
neleus-db --db ./db policy eval
# [Fail] clinical-encrypted   require-encryption-at-rest head=(database)  Encryption at rest is not enabled.
# [Pass] named-agents         require-principal          head=clinical/a  All 12 retrieval(s) name a principal.
# — 7 pass / 1 warn / 1 fail
```

The console's **Monitor** view runs this on a timer and streams new violations
live next to the pass/warn/fail summary.

## The event log

Every recorded violation appends to `meta/events.jsonl`, an append-only,
hash-chained log: each entry carries the hash of the previous one, so deleting
or altering an entry breaks the chain.

```bash
neleus-db --db ./db events list
neleus-db --db ./db events verify     # walks the chain; errors if tampered
```

Over HTTP: `GET /v1/events` returns the log; `?since=<seq>` returns only newer
entries; `?wait=<secs>` (≤30) long-polls for the live feed.

## Alerting

Set `"webhook": "http://host:port/path"` on the policy set. Each recorded
violation is POSTed there as JSON, off the write path (delivery never adds
latency to the write). Delivery is `http://`-only by design — point it at a
local forwarder that terminates TLS to Slack/PagerDuty, the same way inbound
TLS is terminated in front of `serve`.

## CLI

| Command | What it does |
|---|---|
| `policy list` | Print the current policy set. |
| `policy set <file.json>` | Replace the whole set (policy-as-code apply). |
| `policy rm --id <id>` | Remove one policy. |
| `policy eval [--head <h>]` | Evaluate every enabled policy against live state. |
| `events list [--since <seq>]` | List recorded events. |
| `events verify` | Verify the event chain is intact. |
