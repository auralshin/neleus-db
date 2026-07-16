# Regulatory mapping

What an engineering champion hands a compliance buyer. Each row maps a
concrete regulatory requirement to the specific neleus-db mechanism that
produces evidence for it, and the command that produces that evidence.

This is a technical mapping of mechanisms, not legal advice. Whether a given
mechanism satisfies a given obligation for your system is a determination for
your compliance and legal teams. Nothing here is a certification.

## How the evidence is produced

Every retrieval an agent makes can be recorded as a content-addressed
`QueryManifest` — principal, query, the commit it ran against, and every
chunk returned — and committed to history. Commits are BLAKE3 content-
addressed and immutable; a checkpoint chain (an append-only, ed25519-signed
hash chain over each head) makes any rewrite of that history detectable. The
whole period exports as a single signed bundle that an auditor verifies
**offline** with a standalone binary — no access to your systems, no trust in
the vendor.

```
# record retrievals as you serve them
neleus-db search hybrid --head main --query "..." --audit
neleus-db commit new --head main --author agent --message "..." --manifest <audit-manifest> --sign-key agent.key

# anchor history
neleus-db checkpoint new --head main --sign-key agent.key

# produce auditor-ready evidence for a period
neleus-db audit export --head main --from <unix> --to <unix> --out 2026-q1.nelaudit --sign-key agent.key
neleus-verify 2026-q1.nelaudit --public-key <hex> --require-signature
```

## EU AI Act (Regulation (EU) 2024/1689)

| Requirement | Mechanism | Evidence command |
|---|---|---|
| Art. 12(1) — automatic recording of events ("logs") over the lifetime of a high-risk system | Each retrieval writes a content-addressed `QueryManifest` committed to the head's immutable history | `audit log --head <h>` |
| Art. 12(2) — traceability of functioning appropriate to the intended purpose | Each record links principal, query, the exact data version queried (commit root), filters, and every returned chunk hash; chunks resolve to exact bytes | `audit export` → `retrievals.jsonl` |
| Art. 12(3) / Art. 19 — logs kept and available to authorities | Self-contained signed bundle, offline-verifiable by a third party with no vendor dependency | `audit export` + `neleus-verify` |
| Art. 14 — human oversight (reconstruct what the system presented) | Time-travel retrieval reconstructs exactly what was retrievable at any past commit; chunk proofs prove a specific chunk was in scope | `search --head <commit>`, `proof chunk` |

## HIPAA Security Rule (45 CFR Part 164, Subpart C)

| Requirement | Mechanism | Evidence command |
|---|---|---|
| § 164.312(b) — audit controls (record and examine activity) | Hardware-independent tamper-evident retrieval log anchored in a signed checkpoint chain | `audit export`, `checkpoint verify` |
| § 164.312(c)(1) — integrity (protect ePHI from improper alteration) | All content is BLAKE3 content-addressed; any alteration changes the hash and breaks the commit/checkpoint chain | `checkpoint verify --require-signatures` |
| § 164.312(a)(1) — access control (unique user ID, authorization) | API-key principals with reader/writer/admin roles and hard tenant partitioning; the acting principal is recorded on every retrieval | `auth list-keys`, audit `principal` field |
| § 164.316(b)(2) — retention (6 years) | Engine-enforced retention floor on session/episodic records; canonical history is never auto-removed | `retention_min_secs` in `meta/config.json` |
| § 164.312(a)(2)(iv) — encryption | AES-256-GCM / ChaCha20-Poly1305 per object, Argon2id master key | `meta/config.json` encryption block |

## SEC / OCC model risk (SEC 17 CFR 240.17a-4; OCC/Fed SR 11-7 lineage)

| Requirement | Mechanism | Evidence command |
|---|---|---|
| 17a-4 — records preserved in a non-rewriteable, non-erasable form (WORM) | Content-addressed immutable objects; history is append-only and tamper-evident, not overwriteable in place | `audit export` |
| Model risk — record the inputs to each model decision | The retrieved context for each decision is recorded with cryptographic linkage to the exact data version used | audit `queried_commit` + `hits` |
| Examination support — reconstruct a point in time | Any historical commit is queryable (time-travel) and provable offline | `search --head <commit>`, `proof verify-chunk` |

## NIST AI RMF (AI 100-1) — measurement support

The RMF is a voluntary framework, not a prescriptive control set; neleus-db
produces evidence that supports the **Measure** and **Manage** functions:

| Function | Mechanism |
|---|---|
| MEASURE 2.x — traceability and documentation of AI system behavior | Per-retrieval audit records with cryptographic provenance |
| MANAGE 4.x — monitoring and incident response | Compliance summary surfaces chain-integrity status; a broken chain is a detectable tamper event |

## The verifiability gap

No shipping agent-memory product (Mem0, Zep, Supermemory, Letta, Cognee) or
general database (SQLite/SQLCipher, Postgres) offers cryptographic tamper-
evidence of stored memories as of mid-2026 — see
[BENCHMARKS.md](../BENCHMARKS.md#3-the-verifiability-gap) and the research it
cites (arXiv 2605.11032, which names this as an open problem and describes
the BLAKE3 + ed25519 Merkle-DAG architecture neleus-db ships). Encryption,
SOC 2, and access logging are not tamper-evidence: they protect or record
access, they do not let a third party prove that a stored record has not been
altered since it was written.
