# Retention & Erasure — design

Provenance, retention, and erasure for multi-tenant, multi-user, multi-agent
workloads. Resolves the core contradiction: an append-only, tamper-evident audit
log versus GDPR Art. 17 (right to erasure) and Art. 5(1)(e) (storage limitation).
A compliance database that cannot erase makes its operator non-compliant.

## Status

- **Trace lineage** — shipped (manifest schema v4).
- **Erasure** — shipped. Subject-scoped shred of run *and* document/chunk content
  (`src/erasure.rs`), signed `ErasureRecord` in the event log, index purge, and
  the `prove_chunk` commitment-only downgrade.
- **Per-user retention (TTL sweep)** — designed here, not built.
- **Deferred** — swarm write concurrency; trace-query index.

## Principle

Separate the **commitment** from the **content**. Erase the prompt/output bytes;
keep the hash, the manifest, the commit, and the signed checkpoint over them. You
can still prove "an output existed at commit C, by principal Q, under policy P, at
time T" without revealing what it said.

Retention and erasure are one mechanism:

- **Right to be forgotten** = on-demand erasure (a request fires it).
- **Storage limitation / per-user retention** = scheduled erasure (a clock fires it).
- A **regulatory floor** and **legal holds** constrain both.

Per-user TTL also bounds database growth, so this is also the answer to unbounded
append-only storage.

## Identity hierarchy

- **Client = tenant.** Already first-class: auth keys are tenant-bound (hard
  partition to `<tenant>/` heads, forced search filter); `ChunkMetadata.tenant`.
- **User = data subject.** New. Writes (runs/docs) carry an optional `subject`
  alongside `tenant`. Both erasure scoping and per-user retention key on it.

A tenant-scoped key may only manage its own tenant's subjects.

## Trace lineage (shipped, for reference)

`RunManifest` v4 carries `trace_id` (groups runs of one task), `parent_span` (the
parent run's manifest hash — a verifiable span edge), and `delegated_from` (the
agent that handed off). Each run records its *declared* model/provider; neleus
does not attest which remote model actually ran.

## Encryption model (determines the mechanism)

Per-blob keys are `HKDF-SHA256(master_key, per-blob random salt, info=algorithm)`,
with the salt stored in the blob envelope. Destroying one blob's salt/envelope
makes that ciphertext unrecoverable while every other blob is untouched — so
crypto-erase is a per-blob operation requiring no master-key rotation. There is no
blob-delete path today: the CAS is append-only and GC only removes *unreachable*
objects. Erasure is the deliberate, authorized, audited deletion of a *reachable*
committed blob.

## Erasure

### ErasureRecord (signed tombstone)

The keystone: it is what distinguishes authorized erasure from tampering. An
erased blob is byte-identical to a tampered-away blob; the difference is a valid
signed record covering it.

```
ErasureRecord {
  scope:        { tenant, subject? } and/or explicit blob hashes
  blobs:        [Hash]          # the content blobs shredded
  reason:       request | ttl | account-closure | ...
  method:       crypto-shred | physical
  requested_by, authorized_by
  requested_at
  signature
}
```

Content-addressed and anchored in the checkpoint chain, so the erasure itself is
tamper-evident and provable (demonstrating compliance is itself a GDPR
obligation).

### Mechanism

- Encryption **on** → drop the per-blob salt/ciphertext (crypto-shred; residue is
  undecryptable noise, or removed).
- Encryption **off** → physically overwrite/delete the bytes.
- Either way the manifest's hash reference stays in the signed chain.

### Scoping (subject → blobs) — shipped

To erase subject X, `scan_subject_blobs` walks every head's history and partitions
content blobs into X's vs everyone else's: a `RunManifest` by `subject`, a
`DocManifest` (its chunk + original blobs) and standalone `ChunkManifest` by
`metadata.subject`. Only blobs unique to X are shredded — a blob shared via dedup
stays. A `subject → [blob hashes]` serving-plane index is a later optimization.

### Index purge (mandatory) — shipped

The BM25/vector index holds content-derived data (terms, embeddings). After
shredding, `erase_subject` calls `Engine::reindex_all_heads`: it deletes the
segment/head files (and their in-memory caches) and rebuilds every head. The
rebuild's chunk reader skips any blob that is gone **and** covered by an erasure
record (`covers()`), so erased terms/vectors never re-enter the index. The
serving plane is rebuildable and not hashed into identity, so this is mechanical.

An `Engine` `index_gate` (RwLock) serializes the deletion against readers:
`segment_set` holds it shared until every segment is loaded into an `Arc` (after
which a search is memory-only), and the reindex holds it exclusive, so a
concurrent query never loads a segment file mid-delete.

### Modeling rule: immutable fields must be PII-free

Anything that survives erasure (timestamps, model, policy decisions, principal id)
must contain no personal data, or the subject cannot truly be erased. Principal =
opaque id, not an email. All PII lives only in erasable blobs.

## Retention

### Policy

Per scope, two bounds:

```
Retention {
  scope:      global | tenant:<t> | subject:<t>/<u>
  floor_secs? # min — regulatory must-keep (SEC/HIPAA). Cannot erase before this.
  ttl_secs?   # max — storage limitation. Auto-erase after this. ("store 30 days")
}
```

Resolution: **subject override → tenant default → global default.** The common
case for "clients have many users" is a single tenant-level rule
(`tenant:acme { ttl_secs: 30d }` covers all of Acme's users); per-subject entries
are sparse overrides only (legal hold, a specific user's request). This scales to
millions of users with a handful of rules. Lives in the policy engine
(`policy.rs`); generalizes the existing `RetentionFloor` rule.

### TTL sweep

A periodic pass (background thread in `serve`, plus a CLI `retention sweep` for
cron/air-gapped) finds records past their resolved `ttl_secs` that are also past
any `floor_secs` and not under legal hold → crypto-shred + `ErasureRecord` +
event. Clock is per-record age (a run created at T is erasable at T + ttl), which
matches "store N days." Per-user "delete everything on account closure" is the
on-demand erasure path.

## Reconciliation (floor vs ttl, legal holds)

`floor_secs` and `ttl_secs` genuinely conflict (keep 7 years vs delete after 30
days). The policy engine reconciles:

- **Validate at apply time:** reject `ttl_secs < floor_secs` for an overlapping
  scope; surface as a `policy_violation` naming both rules.
- **Defer, don't drop:** a record whose TTL fired but is under a floor or legal
  hold is deferred — auto-erased the instant the floor expires — and the deferral
  is a signed, audited decision.

## Verification semantics

- **Commitment proofs** (manifest → commit → checkpoint) verify fully after
  erasure.
- **Content proofs** (`prove_chunk` with `include_content`) degrade to
  commitment-only: when the blob is erased + covered, the proof sets
  `content_erased` and omits `chunk_bytes`; `verify_chunk_proof` still validates
  the manifest → commit chain and rejects a content-erased proof that smuggles
  bytes back in.
- `neleus-verify` and the bundle format learn the erased state: blob absent + a
  valid signed `ErasureRecord` covering it = **valid (erased)**; blob absent
  without one = **tampered**. This is the change that keeps tamper-evidence intact
  through erasure.

## Surface (sketch)

- `POST /v1/erasure { tenant, subject?, blobs?, reason }` → `ErasureRecord`.
- `GET /v1/erasure` → erasure records (proof of compliance).
- Policy `Retention { scope, floor_secs?, ttl_secs? }` rule; applied via
  `POST /v1/policy` / `policy set`.
- CLI `retention sweep`, `erasure request`, `erasure verify`.

## Open decisions

1. Scope granularity: tenant-default + sparse per-user override (recommended,
   scales) vs true per-user config everywhere.
2. TTL clock: per-record age (recommended) vs per-user rolling (since last
   activity).
3. Sweep home: background thread in `serve` and CLI both (recommended) vs CLI only.
4. Conflict default: block impossible configs at apply; defer individual records
   under holds.
5. Erasure default method: physical when encryption off, crypto-shred when on;
   policy may force physical.

## Phasing

1.  `subject` tagging + `ErasureRecord` + per-blob shred (runs) + the verifier
   "erased = valid" change. (The core.)
2.  Document/chunk erasure + index purge + `prove_chunk` commitment-only
   downgrade.
3. `Retention { floor, ttl }` policy rule + resolver + the TTL sweep.
4. Reconciliation/defer logic.

Near-front, not premature: any client placing EU end-users in the database asks
for "delete per user after N days" early. Table stakes for the wedge.

## Deferred / non-goals

- **Swarm write concurrency** — the single global write lock serializes commits.
  Sharding it per-head is blocked not by the lock but by the WAL + crash recovery,
  which assume single-writer ordering (interleaved transactions or per-head WAL
  segments). Build when a high-concurrency-swarm customer hits it; gate on the
  `multiprocess_contention` bar.
- **Trace-query index** — fetch all runs for a `trace_id` without walking commits.
  v1 reuses the `audit::collect` walk over a head+window; a serving-plane index is
  the later optimization.
- **Attesting remote model identity** — out of scope; neleus records the declared
  model, not a cryptographic attestation of the remote one.
- **Erasing already-exported `.nelaudit` bundles** — off-system; a
  disclosure-management problem, not a database one.
