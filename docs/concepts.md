# Concepts

The mental model. Read this before [../DESIGN.md](../DESIGN.md), which goes
to the byte level.

## Content addressing

Everything durable is identified by the BLAKE3 hash of its bytes. A blob's
name is `blake3("blob:" ‖ bytes)`; a commit's name is
`blake3("commit:" ‖ dag_cbor(commit))`. The domain prefix (`blob:`,
`commit:`, `manifest:`, …) keeps types from colliding.

Two consequences fall straight out:

- **Dedup is free.** Identical content writes once.
- **Tampering is detectable.** Change a byte, change the hash. A reference to
  the old hash no longer resolves to the altered bytes — it resolves to
  nothing, or to the original if it still exists. You cannot quietly swap
  what a hash points to.

This is the whole trust story. Proofs, checkpoints, and signed commits are
all built on "the name is the hash of the content."

## Objects and manifests

- **Blobs** — raw bytes (chunk text, embeddings, values, prompts).
- **Manifests** — typed DAG-CBOR objects that reference blobs by hash:
  - `DocManifest` — a chunked document (list of chunk-blob hashes + metadata).
  - `ChunkManifest` — one chunk with an optional embedding and metadata.
  - `SummaryManifest` — a hierarchical summary pointing at its children.
  - `RunManifest` — one model invocation: prompt, system prompt, params,
    inputs, outputs, retrieved chunks.
  - `QueryManifest` — one retrieval: principal, query, the commit queried,
    every returned chunk. This is the audit record.
- **State** — a versioned key/value map stored as a content-addressed prolly
  tree (a Merkle B+-tree).
- **Commits** — `{parents, author, message, state_root, manifests, …}`,
  optionally ed25519-signed. The git-shaped unit of history.

## State: a versioned KV with proofs

State is an ordered, content-addressed prolly tree (Merkle Search Tree). Node
boundaries are derived from `hash(key)`, so the shape is a pure function of the
key set — the same keys always yield the same root, regardless of write order.
High fanout keeps it shallow (depth `~log32(n)`), so reads, writes, and proofs
all follow a short root→leaf path. Small values inline into leaves, large ones
become blobs. Because every node's hash commits to its subtree, you can produce
an O(log n) **membership or non-membership proof** for any key against a state
root, verifiable from the root hash alone.

Session memory (`session append/list/gc`) lives in a reserved keyspace of the
state store, so it inherits proofs, history, and encryption for free, and
adds TTL on top.

## The two planes

This is the load-bearing idea.

```
CANONICAL plane — immutable, content-addressed, the source of truth
  blobs/  objects/  refs/        ← hashed into identity; the trust anchor

SERVING plane — derived, rebuildable, fast, never hashed into identity
  index/segments/  index/heads/  ← BM25 + HNSW + metadata; delete & rebuild
  in-memory caches               ← segments, state objects, blobs
```

The canonical plane is frozen discipline: its byte encoding is locked by
golden tests, because changing it would invalidate every existing hash and
proof. The serving plane is the opposite — it is *derived* from canonical
data and never hashed into any identity, so it is free to use mutable,
cache-friendly, SIMD-friendly layouts and proven index libraries. Delete
`index/` and you lose nothing but warm-up time.

Every query runs against a commit root, which gives you **snapshot isolation**
and **time-travel** (`search --head <commit-hash>`) for free.

## Retrieval

- **BM25** over an inverted index with MaxScore pruning (cost tracks result
  density, not corpus size).
- **Vector** via a hand-rolled HNSW graph; at production dims (≥256) the graph
  traverses on SQ8 int8 codes and reranks the top candidates in f32. Recall
  is pinned in tests against an exact brute-force oracle (recall@10 ≥ 0.90).
- **Hybrid** runs both concurrently and fuses with Reciprocal Rank Fusion.
- **Filters** (tenant, doc type, language, ACL, validity instant) are
  prefilters — applied before scoring, never after, so they never leak
  existence through scores or timing.

## Verifiability

Four layers, each building on content addressing:

1. **Signed commits** — ed25519 over the commit's canonical payload hash.
2. **Checkpoint chains** — an append-only object chain per head, each
   checkpoint committing to its predecessor's hash and (optionally) signed. A
   transparency-log spine: rewriting history breaks the chain even for
   someone holding the commit signing key. Publish the latest hash anywhere
   durable to externally anchor everything below it.
3. **Chunk proofs** — a self-contained bundle proving `(commit, chunk)`:
   commit hash → first-parent ancestry → the manifest that lists the chunk →
   the chunk bytes, every link a hash equation. Verifiable offline.
4. **Audit records** — `QueryManifest`s committed to history, exportable as a
   signed bundle. The audit log is itself content-addressed and provable.

## Local and hosted are the same engine

Embed the crate (`Engine::open`) and you get the full API in-process. Run
`neleus-db serve` and the HTTP server is a thin layer over the *same*
`Engine` — local and hosted behavior cannot drift. Replication is git-style
push/pull of content-addressed packs, fast-forward only.
