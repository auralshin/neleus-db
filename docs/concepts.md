# Concepts

The model in brief. [../DESIGN.md](../DESIGN.md) covers the byte level.

## Content addressing

Every durable object is named by the BLAKE3 hash of its bytes, with a type
prefix (`blob:`, `commit:`, `manifest:`, ...) so types cannot collide. Change a
byte and the name changes, so a reference can never silently point at
different content.

Blobs are stored as `salt || content`. The salt is a keyed hash of the content
under a key derived from the database `secret` and the head's namespace (the
part before the first `/`). So identical content dedups within a namespace but
gets different ids across tenants, and an id cannot be confirmed from guessed
content without the secret.

## Objects

- **Blobs**: raw bytes (chunk text, embeddings, prompts, outputs).
- **Manifests**: typed DAG-CBOR objects that point at blobs:
  `DocManifest` (a chunked document), `ChunkManifest`, `SummaryManifest`,
  `RunManifest` (one model call: prompt, params, inputs, outputs, retrieved
  chunks), and `QueryManifest` (one retrieval: principal, query, commit
  searched, hits). The last is the audit record.
- **State**: a versioned key/value map stored as a prolly tree (a Merkle
  search tree). The same key set always gives the same root. Node boundaries
  are keyed by the database secret so a writer cannot force huge nodes. Any
  key has an O(log n) membership or non-membership proof against a root.
  Session memory lives in a reserved keyspace of state.
- **Commits**: `{parents, author, message, state_root, manifests, ...}`,
  optionally ed25519-signed. Each commit's state also indexes every manifest
  committed so far under `__manifests__/`.

## Two planes

- **Canonical**: `blobs/`, `objects/`, `refs/`. Content-addressed and the
  source of truth. Its encoding is fixed by golden tests.
- **Serving**: `index/` (BM25, HNSW, metadata) and in-memory caches. Derived
  from canonical data and never hashed into any identity. Deleting `index/`
  only costs a rebuild.

Every query runs against a commit, so you get snapshot reads and can search
any past commit of a head.

## Retrieval

- **BM25** (`semantic` mode) over an inverted index.
- **Vector** search over an HNSW graph, using int8 (SQ8) codes at 256+
  dimensions with f32 rerank. Embeddings are supplied by the caller.
- **Hybrid** fuses both with Reciprocal Rank Fusion.
- **Filters** (tenant, doc type, language, ACL tags, validity time) apply
  before scoring, and BM25 statistics cover only what the caller may see.

## Verifiability

1. **Signed commits**: ed25519 over the commit's payload hash.
2. **Checkpoints**: an append-only, optionally signed chain per head. Each one
   links its predecessor, holds an RFC 6962 Merkle root over every
   checkpointed commit, and pins the newest retrieval record and event-log
   entry. Keep a checkpoint hash outside the database to detect later
   rewrites.
3. **Chunk proofs**: one commit plus one state path to the manifest's
   `__manifests__/` entry, the manifest, and optionally the chunk bytes.
   Proof size does not grow with history. A proof can carry an anchor that
   ties the commit to a checkpoint.
4. **Retrieval records**: a per-head chain (`refs/records/<head>`) with a
   gapless `seq`, kept off the commit history. Every search on a head adds
   one. Audit bundles export a window of them with the edge records that
   show nothing was dropped.

What a chunk proof shows is that a chunk was in the corpus at a commit. It does
not show the chunk was retrieved; the retrieval record does that.

## Same engine, local or served

`Engine::open` gives the full API in process. `neleus-db serve` is a thin HTTP
layer over the same `Engine`. Replication is push/pull of content-addressed
packs, fast-forward only, between databases that share the same `secret`
(`db init --replica-of <url>`).
