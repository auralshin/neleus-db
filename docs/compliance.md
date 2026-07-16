# Compliance

How retrieval becomes auditable evidence, and how an auditor verifies it
without trusting you.

## The loop

1. **Record.** Run searches with `--audit`. Each writes a content-addressed
   `QueryManifest` — principal, query, the commit queried, filters, and every
   returned chunk hash. Attach it to a commit to make it durable history.
2. **Anchor.** Append signed checkpoints to the head. The checkpoint chain is
   append-only and each entry commits to its predecessor, so history rewrites
   are detectable even by someone holding the commit signing key.
3. **Export.** `audit export` bundles a time period — the audit records, the
   commit ancestry that anchors them, and the checkpoint chain — into one
   self-contained `.nelaudit` file, optionally ed25519-signed.
4. **Verify.** `neleus-verify` (or any third party) checks the bundle
   **offline**: every hash is re-derived from bytes in the bundle. No
   database, no network, no trust in the vendor.

```bash
neleus-db search hybrid --head main --query "…" --audit          # 1
neleus-db commit new --head main --author agent --message audit --manifest <qm> --sign-key agent.key
neleus-db checkpoint new --head main --sign-key agent.key        # 2
neleus-db audit export --head main --from <unix> --to <unix> \
    --out 2026-q1.nelaudit --sign-key agent.key                  # 3
neleus-verify 2026-q1.nelaudit --public-key <hex> --require-signature   # 4
```

## What the bundle contains

A single file (`magic | version | count | entries… | blake3 footer |
optional ed25519 trailer`). Entries:

- `meta.json` — head, tip, period, counts, checkpoint tip, tool version.
- `summary.txt` — the human-readable period summary.
- `retrievals.jsonl` — one line per retrieval (principal, time, commit, hits).
- `objects/<hash>` — the canonical commit ancestry + the manifest bytes.
- `checkpoints/<hash>` — the signed checkpoint chain for the period.

## What the verifier proves

Independently, with no access to your systems:

1. The bundle hasn't been altered (BLAKE3 footer, and signature if present).
2. Each record's manifest bytes hash to its claimed hash, and decode as a
   `QueryManifest` (pinned by canonical round-trip).
3. Each carrying commit lists that manifest, and is reachable from the
   declared tip by first-parent links carried in the bundle.
4. The checkpoint chain is intact — hashes, prev-links, and sequence numbers
   all consistent — and every signed checkpoint verifies under the key.
5. Every record falls inside the declared period.

## The law catalog

`compliance` runs checks against **live audit data** for 13 frameworks across
10 jurisdictions:

| Jurisdiction | Frameworks |
|---|---|
| EU | EU AI Act, GDPR |
| US (federal) | NIST AI RMF, HIPAA, SEC 17a-4 / OCC SR 11-7 |
| US — Colorado | Colorado AI Act (SB 24-205) |
| US — California | CCPA / CPRA (ADMT) |
| UK | UK GDPR / DPA 2018 |
| Canada | AIDA (Bill C-27) |
| China | Interim Measures for Generative AI Services |
| Singapore | Model AI Governance Framework |
| Brazil | LGPD |
| International | ISO/IEC 42001 |

Each framework declares which checks apply, at `required` or `recommended`
severity. The checks are real, evaluable properties:

- audit logging present
- tamper-evident checkpoint chain
- checkpoints signed
- encryption at rest
- principal recorded on every retrieval
- retention policy configured
- each decision linked to its exact data version

A framework's **overall** status is driven by its required checks:
`pass` (satisfied) / `warn` (in-review) / `fail` (gap).

```bash
neleus-db compliance frameworks
neleus-db compliance status --head main
neleus-db compliance check --head main --framework eu-ai-act
neleus-db audit report --head main --framework hipaa --out hipaa.md
```

For the article-by-article mechanism mapping, see
[regulatory-mapping.md](regulatory-mapping.md).

## Retention

`retention_min_secs` in `meta/config.json` sets a floor: session GC will not
physically remove a record until it is at least that old, even after its TTL
expires. Expiry hides a record from reads; retention controls deletion —
two different requirements (GDPR storage limitation vs HIPAA/SEC retention)
reconciled by separating them. Canonical history (commits, manifests, audit
records) is never auto-removed.

## The console

`neleus-db serve` bundles the compliance console into the binary and serves it
at `/` (run `serve --open`). It is the compliance-officer surface: a chain-intact
overview with the per-jurisdiction status panel, the audit log + export, the
report generator, the engineer's proof inspector, and the policy views (live
monitor + violations). Source is in-tree at [../console](../console). For
write-time monitoring and enforcement see [policy.md](policy.md).

## Scope

This is generated evidence tooling that maps mechanisms to requirements. It
is not legal advice and not a certification. Whether a mechanism satisfies an
obligation for your system is a determination for your compliance and legal
teams.
