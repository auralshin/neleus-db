# Documentation

Start here, in roughly this order:

| Doc | What it covers |
|---|---|
| [getting-started.md](getting-started.md) | Install, init, ingest, search, prove, sign, serve — one page, end to end. |
| [concepts.md](concepts.md) | The mental model: content addressing, commits, the two planes, checkpoints, proofs. Read this before the design doc. |
| [cli.md](cli.md) | Every `neleus-db` command and the `neleus-verify` binary, with flags. |
| [http-api.md](http-api.md) | `neleus-db serve` endpoint reference: auth, CORS, tenancy, every route. |
| [policy.md](policy.md) | Policy-as-code: monitor + enforce rules at write time, the tamper-evident event log, webhook alerting. |
| [security.md](security.md) | Threat model and the control for each attacker. |

Deeper references live at the repo root:

- [../DESIGN.md](../DESIGN.md) — Merkle model, storage planes, WAL recovery, the exact on-disk shapes.
- [../BENCHMARKS.md](../BENCHMARKS.md) — measured numbers vs SQLite, scale points, and the competitor/verifiability-gap analysis.
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — the rule about not breaking the byte format, and the test bar.

Forward-looking design notes (specs, not yet built):

- [design/retention-and-erasure.md](design/retention-and-erasure.md) — per-user/multi-tenant retention, GDPR erasure (crypto-shred + signed tombstone), and trace lineage.

The web console is bundled into the binary and served by `neleus-db serve` (its
source lives in-tree at [../console](../console)); see the Web console section
of [http-api.md](http-api.md) and the policy views in [policy.md](policy.md).
