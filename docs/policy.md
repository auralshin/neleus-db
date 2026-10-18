# Policy enforcement

Policies are rules that neleus checks continuously (monitor) or at write time
(enforce, which rejects the write). They live in `meta/policy.json` and are
set with `policy set`, `POST /v1/policy`, or the console's Policies view.
Violations go to a hash-chained event log and can trigger a webhook.

## Policy set

```json
{
  "webhook": "http://127.0.0.1:9000/hook",
  "policies": [
    { "id": "encrypted", "rule": { "kind": "require-encryption-at-rest" },
      "mode": "enforce" },
    { "id": "retention", "rule": { "kind": "retention-floor", "min_secs": 220752000 },
      "mode": "enforce" },
    { "id": "named-agents", "heads": ["clinical/*"],
      "rule": { "kind": "require-principal" }, "mode": "enforce" },
    { "id": "signed-history", "heads": ["clinical/*"],
      "rule": { "kind": "require-signed-checkpoints" },
      "mode": "monitor", "severity": "recommended" }
  ]
}
```

- `heads`: exact names, `prefix*`, or `*`/omitted for all. Global rules ignore
  it.
- `mode`: `enforce` rejects the write (HTTP 403, code `policy_violation`);
  `monitor` allows it and logs the violation.
- `severity`: `required` (default) or `recommended`. Informational only.
- `enabled`: default `true`.

## Rules

| `kind` | Checks | At write time |
|---|---|---|
| `require-tamper-evident-chain` | the head's checkpoint chain verifies | no |
| `require-signed-checkpoints` | every checkpoint on the head is signed | no |
| `require-signed-commits` | the head's tip commit is signed | no |
| `require-encryption-at-rest` | encryption is enabled (global) | yes |
| `retention-floor` (`min_secs`) | config `retention_min_secs` ≥ `min_secs` (global) | yes |
| `require-principal` | the write has an authenticated principal; continuously, every retrieval in the last 30 days names one | yes |
| `require-provenance` | a run declares a provider, inputs, or retrieved chunks | yes, runs only |

`retention_min_secs` only stops session GC from removing younger records.
Erasure does not consult it.

## Where enforcement applies

Write-time rules run on every mutating HTTP route (documents, runs, commits,
state, blobs, sessions, checkpoints, pack) and on searches, since a search
writes a record. The CLI's `state set`, `commit new`, and `session append` commands
are gated too, with principal `cli`. Other CLI writes and the embedded library
are not gated.

A global rule in `monitor` mode is not logged on every write; `policy eval`
reports it.

## Monitoring

```bash
neleus-db --db ./db policy eval [--head <h>]
# [Fail] encrypted  require-encryption-at-rest  head=(database)  Encryption at rest is not enabled.
# — 3 pass / 0 warn / 1 fail
```

HTTP: `POST /v1/policy/evaluate`. The console's Monitor view runs it on a timer.

## Event log

Violations append to `meta/events.jsonl`. Each entry carries the previous
entry's hash, so editing or deleting one breaks the chain. Each checkpoint pins
the log's newest entry, so `checkpoint verify` also catches a rewrite below
that point. Erasure records live in the same log.

```bash
neleus-db --db ./db events list [--since <seq>]
neleus-db --db ./db events verify
```

HTTP: `GET /v1/events` with `?since=<seq>`, `?wait=<secs>` (long-poll, max 30),
`?verify=1`.

## Webhook

Each logged violation is POSTed as JSON to `webhook` on a background thread,
so it never delays the write. Only `http://` is supported; use a local
forwarder for HTTPS targets. The URL is shown only to admins.

Other commands (`policy list`, `policy rm --id <id>`) are in [cli.md](cli.md).
