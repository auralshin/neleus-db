# Design

This is the single design document for the current codebase. It describes
implemented architecture only; proposal-only ideas are listed as future work.

## 1. Core Model

Neleus DB separates canonical truth from derived serving structures.

Canonical data is immutable and content-addressed:

- `BlobStore` stores raw bytes under `blobs/`.
- `ObjectStore` stores typed DAG-CBOR objects under `objects/`.
- `ManifestStore` stores document, chunk, summary, run, and query manifests.
- `StateStore` stores versioned key/value state.
- `CommitStore` stores a git-like commit graph over state and manifests.

Derived data is rebuildable:

- `engine::Engine` stores retrieval indexes under `index/`.
- Index data is encrypted when database encryption is enabled, but it is not
  part of canonical identity.
- Deleting `index/` loses warm query performance, not durable truth.

Every externally meaningful record can be traced back to canonical bytes and
verified by hash equations.

## 2. On-Disk Layout

```text
<db_root>/
  blobs/                         raw content-addressed payloads
    aa/bb/<hash>                 loose blob files
    pack/                        consolidated blob packs
  objects/                       typed content-addressed objects
    aa/bb/<hash>                 loose object files
    pack/                        consolidated object packs
  refs/
    heads/<name>                 commit refs
    states/<name>                staged state refs
    checkpoints/<name>           checkpoint-chain refs
  index/
    segments/<hash>              immutable retrieval index segments
    heads/<commit>               segment set serving a commit
  wal/                           ref-update WAL records
  meta/
    config.json                  database config
    recovery.lock                open/recovery lock
```

Loose CAS files are the write path. `db repack` consolidates loose blobs and
objects into pack files; reads check loose files and then pack indexes.

## 3. Canonical Encoding and Hashing

Canonical serialization uses DAG-CBOR through `src/canonical.rs`. Hashing uses
BLAKE3 plus domain separators so different object families cannot collide by
sharing bytes.

Domain tags include:

- `blob:`
- `manifest:`
- `manifest_leaf:`
- `state_node:`
- `state_leaf:`
- `state_manifest_leaf:`
- `merkle_node:`
- `commit:`
- `commit_payload:`
- `checkpoint:`
- `checkpoint_payload:`
- `index_segment:`

Representative formulas:

```text
H_blob       = blake3("blob:" || bytes)
H_manifest   = blake3("manifest:" || dag_cbor(manifest))
H_state_node = blake3("state_node:" || dag_cbor(state_object))
H_commit     = blake3("commit:" || dag_cbor(commit))
```

Golden-byte tests in `canonical.rs` lock selected encodings so schema changes
do not accidentally change canonical bytes.

## 4. Database Lifecycle

`Database::init` creates directories and `meta/config.json`, then writes the
empty state root. `Database::open`:

1. Acquires `meta/recovery.lock`.
2. Loads config and validates durability/encryption settings.
3. Creates stores over `blobs/`, `objects/`, `refs/`, and `wal/`.
4. Replays ref WAL entries.
5. Cleans orphan atomic-write temp files.

Config schema version is `3`. Current config fields include:

- `verify_on_read`
- optional `compression = "zstd"`
- optional `encryption`
- optional `durability = "os" | "full"`
- optional `retention_min_secs`

## 5. State Store

State is an authenticated, content-addressed, ordered map: a **prolly tree**
(content-defined Merkle Search Tree / B+-tree) keyed by the raw key. Node
boundaries are content-defined — a key is a boundary at level `L` iff
`key_level(key) > L`, where `key_level` counts leading zero bits of
`hash(key)` in groups of `BITS_PER_LEVEL` (5 ⇒ average fanout 32). Boundary
status is a pure function of the key, so a key set determines a unique tree
shape regardless of write order (history independent ⇒ equal states have equal
roots), and incremental writes touch only the affected root→leaf path. A state
root points to a manifest:

```text
StateManifest {
  schema_version,
  root: Option<Hash>   // content hash of the root node; None = empty
}
```

A node references its children by content hash, so a node's hash commits to its
entire subtree — the tree is its own Merkle commitment, no separate merkle root:

```text
StateNode {
  level,
  items: Leaf([(key, ValueRef)])        // ValueRef = Inline(bytes) | Value(blob hash)
       | Branch([(last_key, child)])     // last_key = max key in the child subtree
}
```

High fanout makes the tree shallow — depth `~log32(n)` (≈2–4 levels for
millions of keys) — so reads, writes, and proofs all follow a short root→leaf
path. Reads descend by routing to the first child whose `last_key >= key`.
Writes copy-on-write that path and re-run the cut rule locally (splits and
merges fall out of re-chunking); an empty base bulk-builds the canonical tree
bottom-up in one pass. Values up to `INLINE_VALUE_MAX` (`512` bytes) are inline;
larger values go to `BlobStore`. `del` removes the entry — no tombstones,
absence is the only "not present" — and an emptied state returns to the
canonical empty root. Range scans (`scan_prefix`) walk leaves in key order.
Structural sharing across versions makes diffs, sync, and GC cheap. Decoded
nodes and manifests are cached in process.

## 6. State Proofs

`StateProof` verifies membership or non-membership against a state root without
trusting the caller's result — from the root hash alone.

It carries:

- manifest schema version and the root hash it anchors to
- the search path: the actual `StateNode`s from the root to the leaf that holds
  the key, or that would hold it
- final outcome (`Found(value commitment)` or `Missing`)

Verification recomputes each path node's content hash, checks the first against
the committed root and each branch's routing pointer (`route` by `last_key`)
against the next node, and validates the terminal leaf: the key is present
(membership) or absent in the leaf its range routes to (non-membership). Both
cases are a single root→leaf path — proof size is the tree height
`O(log_B n)`, independent of the number of writes.

## 7. Manifests

`MANIFEST_SCHEMA_VERSION` is `4`.

Implemented manifest families:

- `DocManifest`: source document, original blob, chunking spec, chunk hashes,
  and optional document-level metadata.
- `ChunkManifest`: chunk text, byte range, optional embedding, optional
  metadata.
- `SummaryManifest`: summary text, optional embedding, child links, hierarchy
  level, optional metadata.
- `RunManifest`: model invocation with prompt, inputs, outputs, tool calls,
  provider metadata, retrieved chunks, SDK version, agent id, and (v4) trace
  lineage — `trace_id` (groups runs of one task across agent handoffs and model
  switches), `parent_span` (the parent run's manifest hash, a verifiable span
  edge), and `delegated_from` (the agent that handed off). The model/provider on
  each run is the *declared* identity; neleus records what the caller stated, it
  cannot cryptographically attest which remote model actually ran.
- `QueryManifest`: content-addressed retrieval audit record containing query
  text or embedding, filters, principal, commit, mode, top-k, and returned
  chunk hashes.

`ChunkMetadata` supports retrieval filtering:

- tenant
- doc type
- language
- valid-from / valid-to
- expiration
- ACL tags

Empty ACL means public. Non-empty ACL requires overlap with the caller's ACL
filter.

## 8. Commits and Signing

Commits are canonical objects:

```text
Commit {
  schema_version,
  parents,
  timestamp,
  author,
  message,
  state_root,
  manifests,
  signature?,
  payload_hash?
}
```

Signed commits use `commit_payload:` over the unsigned commit body. The
payload hash is stored so verifiers can re-derive the exact bytes that were
signed.

Signing is pluggable through:

- `CommitSigner`
- `CommitVerifier`

The built-in implementation uses ed25519 through `Ed25519Signer` and
`Ed25519Verifier`. Key files are written with restrictive permissions.

## 9. Retrieval Engine

`engine::Engine` is the resident serving layer over a `Database`.

Index layout:

```text
index/segments/<hash>   immutable IndexSegment
index/heads/<commit>    SegmentSetManifest for that commit
```

A segment set is ordered oldest to newest; newer chunks win on chunk-hash
collisions. Indexes cover the first-parent ancestry of a commit. Each commit
adds a delta segment, and chains longer than `MERGE_THRESHOLD` (`8`) are
merged into one segment.

`IndexSegment` contains:

- chunk rows and metadata columns
- BM25 postings
- normalized vectors
- scalar-quantized vectors for sufficiently large dimensions
- HNSW graph when the segment has at least `256` vectors

Query modes:

- lexical BM25
- vector search with HNSW and exact-scan fallback
- hybrid search using reciprocal rank fusion

Filters are applied before scoring where possible:

- tenant
- doc type
- language
- ACL tags
- validity instant

Hits carry `(commit, chunk_hash, score, preview)`. `Engine::prove` upgrades a
hit to an offline-verifiable chunk proof.

## 10. Session Memory

Session memory is implemented over the state store under the reserved
`__session__/` keyspace.

`SessionRecord` stores:

- session id
- sequence number
- optional role
- content blob hash
- created timestamp
- optional expiration timestamp

Reads filter expired records when a `now` instant is supplied. `session gc`
tombstones expired records and compacts state, but honors
`retention_min_secs`; canonical committed history is not automatically removed.

## 11. Audit and Compliance

Every audited retrieval is a `QueryManifest` committed into canonical history.

`audit` can:

- collect query manifests reachable from a head in a time window
- export a self-contained `NELAUDIT` bundle
- optionally sign the bundle footer with ed25519
- verify the bundle offline without a database or network

Bundle entries include metadata, a summary, retrieval JSONL, canonical commit
and manifest bytes, and checkpoint bytes. Verification re-derives claims from
the carried bytes by hash equations.

`compliance` maps implemented mechanisms to framework checks. It evaluates
live audit data for checks such as:

- audit logging present
- tamper-evident checkpoint chain
- signed checkpoints
- encryption at rest
- principal recorded
- retention configured
- data-version linkage

Compliance reports are mechanism checks, not legal certification.

## 12. Checkpoints

Checkpoints form an append-only hash chain per head under
`refs/checkpoints/<head>`.

Each checkpoint records:

- head name
- commit hash
- previous checkpoint hash
- timestamp
- author
- optional signature
- payload hash

`CheckpointStore::verify_chain` walks from the current checkpoint tip to
genesis, verifies hash links, and optionally requires signatures.

## 13. Chunk Proofs

`retrieval_proof` creates offline-verifiable proof bundles for search hits.

A chunk proof links:

```text
commit -> first-parent ancestry -> manifest -> chunk bytes
```

The prover walks bounded ancestry, carries the relevant commit and manifest
bytes, and optionally includes chunk content. The verifier replays the hash
equations and confirms the chunk is referenced by a reachable manifest.

## 14. Server, Auth, and Tenancy

`server` is a small std-only HTTP/1.1 server around `Engine`.

Properties:

- loopback by default; TLS termination is expected in front for remote use
- bounded headers, bodies, connections, and top-k
- bearer token auth
- single-writer mutex for mutating requests
- CORS support when configured

`auth` stores API keys in `meta/auth.json`.

- Tokens use the `nlk_` prefix.
- Stored records contain BLAKE3 token hashes, not raw tokens.
- Secret comparison is constant-time.
- Roles form a ladder: `reader < writer < admin`.
- Optional tenant binding scopes heads and filters structurally.

Tenant-scoped keys can only access their tenant's head namespace and have
search filters forced to that tenant.

## 15. Sync and Replication

`sync` implements content-addressed push/pull over packs.

Rules:

- ref updates are fast-forward only
- divergent refs are reported, not overwritten
- checkpoint chains merge only when the remote chain contains the local tip
- encryption configs must match exactly

HTTP sync uses the same server API and caps response sizes.

## 16. Crash Safety and Concurrency

File writes use temp-file plus atomic rename. In `full` durability mode, file
and directory syncs are used; `os` mode relies on normal operating-system
flush behavior.

Ref updates write WAL entries before the ref file is changed. `Database::open`
replays WAL records. State mutations do not use a separate WAL because the ref
CAS is the commit point; interrupted writes leave unreachable CAS garbage.

Locks:

- `refs/.refs.lock` protects ref mutation.
- `meta/recovery.lock` protects recovery and migration on open.

## 17. Encryption, Compression, and Integrity

Encryption is optional and configured in `meta/config.json`.

- AEAD: AES-256-GCM or ChaCha20-Poly1305
- password KDF: Argon2id (`m=19456 KiB`, `t=2`, `p=1`)
- per-object keys: HKDF
- randomness: OS CSPRNG through `getrandom`
- key material is zeroized where applicable

Blobs, objects, and index segments are encrypted when encryption is enabled.
Authentication failure is treated as wrong key or tampering.

Compression is optional `zstd`.

When `verify_on_read` is enabled:

- blob reads re-hash bytes with `blob:`
- object reads re-hash typed bytes with the expected tag

## 18. Garbage Collection and Packs

`gc` is reachability-based. It marks live objects from refs, commits, states,
manifests, checkpoints, and derived references, then can prune unreachable
loose files and rewrite packs to keep only live content.

`db pack` and `db unpack` provide a single-file backup/restore format with an
integrity footer. Pack verification checks structure and hashes.

## 19. Current Non-Goals and Future Work

The implementation intentionally does not include:

- Prolly-tree state storage; state proofs remain scan-prefix based.
- In-process TLS; deploy TLS/mTLS in front of the server.
- External KMS/HSM integration.
- Distributed consensus; replication is git-style fast-forward sync.
- Dependency-heavy search libraries; BM25, HNSW, and HTTP are implemented in
  this repository.

These are viable future additions, but they are not part of the current
architecture.
