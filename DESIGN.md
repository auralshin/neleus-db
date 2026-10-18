# Design

## Planes

- **Canonical**: blobs, typed DAG-CBOR objects, manifests, state, commits,
  checkpoints, and retrieval records. Immutable, content-addressed, hashed into
  identity.
- **Serving**: retrieval indexes under `index/` (`engine::Engine`). Derived
  and rebuildable; deleting `index/` costs warm-up time, not data.

## On-disk layout

```text
<db_root>/
  blobs/, objects/              loose files (aa/bb/<hash>) and pack/
  refs/heads/<name>             head commit
  refs/states/<name>            staged state root
  refs/checkpoints/<name>       newest checkpoint
  refs/records/<name>           newest retrieval record
  index/segments/<hash>         immutable index segments
  index/heads/<commit>          segment set serving a commit
  wal/                          ref WAL
  meta/config.json              config, including the database secret
  meta/events.jsonl             hash-chained event log
  meta/auth.json, policy.json   API keys, policies
```

Writes go to loose files; `db repack` moves them into packs.

## Content addressing

Objects are DAG-CBOR (`canonical.rs`) hashed with BLAKE3 under a domain tag,
so objects of different kinds cannot share a hash: `blob:`, `manifest:`,
`manifest_leaf:`, `state_node:`, `commit:`, `commit_payload:`, `checkpoint:`,
`checkpoint_payload:`, `checkpoint_leaf:`, `merkle_node:`, `merkle_root:`,
`index_segment:`.

```text
H_blob     = blake3("blob:" || salt || content)
H_manifest = blake3("manifest:" || dag_cbor(manifest))
H_node     = blake3("state_node:" || dag_cbor(node))
H_commit   = blake3("commit:" || dag_cbor(commit))
```

## Secret and salted blobs

`meta/config.json` holds a random 32-byte `secret`. It derives the state-tree
boundary key and the blob salt keys.

A blob is stored as `salt || content`; its id hashes the whole payload. The
salt is a keyed hash of the content under a key for the head's namespace (the
head name before the first `/`, see `BlobStore::for_head`). The same content in
two tenants gets two ids, and an id cannot be confirmed from content without
the secret. Proofs carry the payload; `ChunkProof::chunk_content` strips the
salt.

Replicas must share the secret (`db init --replica-of <url>`). Sync refuses to
merge databases whose secrets or encryption configs differ.

## State

State is a prolly tree keyed by raw key. A key is a boundary at level `L` when
the leading zero bits of `keyed_hash(boundary_key, key)`, divided by 5, exceed
`L` (average fanout 32). The key is secret, so writers cannot grind keys into
one huge leaf. Boundaries depend only on the key, so equal key sets have equal
roots regardless of write order.

```text
StateManifest { schema_version, root: Option<Hash> }
StateNode { level, items: Leaf([(key, Inline(bytes) | Value(blob))])
                        | Branch([(last_key, child)]) }
```

Values up to 512 bytes are inline; larger ones are blobs. Writes copy the
root-to-leaf path and re-chunk locally. Deletes remove the entry; there are no
tombstones.

A `StateProof` is the node path from the root to the leaf that holds the key
or would hold it, plus `Found` or `Missing`. The verifier re-hashes each node,
checks routing by `last_key`, and inspects the leaf. Its size is the tree
height.

## Manifests

Schema version 5. `DocManifest` (document, chunking spec, chunk hashes),
`ChunkManifest` (text, byte range, optional embedding and metadata),
`SummaryManifest`, `RunManifest` (a model call with prompt, outputs, tool
calls, retrieved chunks, and trace lineage; model identity is as declared by
the caller), and `QueryManifest` (one retrieval record).

`ChunkMetadata` carries tenant, doc type, language, validity window,
expiration, and ACL tags. An empty ACL is public; otherwise the caller's ACL
filter must overlap it.

## Commits and signing

```text
Commit { schema_version, parents, timestamp, author, message,
         state_root, manifests, signature?, payload_hash? }
```

A signature covers `commit_payload:` over the commit with `signature` and
`payload_hash` cleared. The signature's `key_id` names its ed25519 key, so
offline verifiers check signed commits without a store. A server started with
a signing key signs every commit it makes.

A commit that introduces manifests writes a `__manifests__/<hash>` key for each
into its state.

## Retrieval record chain

The server and CLI record every search; there is no opt-out. Library callers
record through `Engine::search`; only `search_*_unrecorded` skips it. Searching
a past commit (`commit` over HTTP, `--at` in the CLI) still records on the head.

`refs/records/<head>` names the newest `QueryManifest`. Each record carries a
gapless `seq` and a `prev` link. A batch writes its manifests, then one ref
update commits it, so searches never add commits to data history. Concurrent
recordings on a head group-commit (`engine/recorder.rs`). A `seq` gap shows a
withheld record; nothing can show a search that was never recorded.

## Checkpoints

`refs/checkpoints/<head>` names the newest checkpoint in a per-head hash chain:

```text
Checkpoint { schema_version, prev, head, commit, sequence, created_at,
             signature?, key_id?, log_root, log_spine, query_tip?, event_tip? }
```

- `log_root` is an RFC 6962 Merkle root over every checkpointed commit, with
  the leaf count sealed in. `log_spine` makes each append O(log J).
- `prove_commit_logged` (inclusion) and `prove_append_only` (consistency) give
  O(log J) offline proofs. `verify_chain` walks the whole chain.
- `query_tip` pins the newest retrieval record and `event_tip` the newest event,
  so truncation below a held checkpoint is detectable.

## Chunk proofs

```text
commit -> state path to "__manifests__/<manifest>" -> manifest -> chunk payload
```

The prover searches ancestry for the introducing manifest, but the proof
carries only the queried commit and one state path, so it does not grow with
history. `prove_chunk_anchored` adds a checkpoint, its inclusion proof for a
logged commit, and the first-parent path from that commit to the proof's
commit.

## Audit bundles

`audit` exports a head's record chain over a time window as a `NELAUDIT` file:
named entries, a BLAKE3 footer, and an optional ed25519 signature over it.

- `meta.json`, `summary.txt`, `retrievals.jsonl`
- `objects/<hash>`: commit and manifest bytes
- `checkpoints/<hash>`: the latest checkpoint only, with
  `checkpoint_inclusion` showing its commit is the last leaf of its log root
- `pinned/<hash>`: the record that checkpoint pins
- `edge/<hash>`: the record before the window and every record from the window
  up to each pin, so the window is provably complete
- with `--anchor`: `anchor/<hash>`, `anchor_inclusion`, and a consistency proof
  from the retained checkpoint

Verification needs no database or network. Against an anchor, truncation or
re-chaining at or below the anchor's pin is rejected.

## Erasure

`erase_subject` shreds blobs referenced only by one subject's runs, documents,
and the retrievals that returned them; shared blobs are kept. It crypto-shreds
when encryption is on and deletes otherwise. Manifests, commits, and
checkpoints stay, so the chain still verifies. A signed `ErasureRecord` in the
event log marks the deletion as authorized rather than tampering. A chunk proof
for erased content sets `content_erased` and carries no bytes. Heads whose
index used a shredded blob are reindexed.

## Retrieval engine

`index/heads/<commit>` lists the segments covering a commit's first-parent
ancestry. Each commit adds a delta segment; chains longer than 8 merge. A
segment holds chunk rows, metadata columns, BM25 postings, vectors (SQ8 codes
at 256 dims and above), and an HNSW graph above 1,024 vectors.

Modes are BM25, vector (HNSW or exact scan), and hybrid by reciprocal rank
fusion. Filters (tenant, doc type, language, ACL, validity) apply before
scoring; filters narrower than 1,024 rows use exact scan.

Tenant isolation: BM25 statistics cover only what the caller may see, tenant
queries read only that tenant's postings, and tenant vector queries use the
tenant's own graph or an exact scan, never the shared graph.

## Server and auth

`server` is std-only HTTP/1.1, loopback by default, with no in-process TLS.
Headers, bodies, connections, and top-k are bounded; mutations take a
single-writer lock. `serve` embeds the web console. API keys (`nlk_`) are
stored as BLAKE3 hashes in `meta/auth.json`. Roles are
`reader < writer < admin`. A tenant-bound key reaches only that tenant's heads,
and its search filter is forced to that tenant.

## Durability

`durability` is process-wide, set at `Database::open`: `full` (default,
`F_FULLFSYNC` on macOS), `barrier` (`F_BARRIERFSYNC` on macOS, full sync
elsewhere), or `os` (no sync).

CAS objects publish with a no-replace rename, falling back to a hard link.
Commits move heads by compare-and-set. Head, staging, and record refs use
`write_atomic` (temp file plus rename) without a WAL; checkpoint refs and
sync's head writes go through the WAL, replayed on open. An interrupted write
leaves only unreachable objects.

## Encryption and integrity

Optional AES-256-GCM or ChaCha20-Poly1305 over blobs, objects, and index
segments. The master key comes from Argon2id (`m=19456 KiB, t=2, p=1`) at
open; per-object keys from HKDF. Compression is optional `zstd`. With
`verify_on_read`, reads re-hash bytes under the expected tag.

## Other components

- **Session memory**: `__session__/` keys. `session gc` deletes expired
  records older than `retention_min_secs`.
- **Event log**: hash-chained; holds policy violations, enforcement actions,
  and erasure records.
- **Sync**: push/pull over packs; refs fast-forward only, divergence is
  reported.
- **GC**: marks from heads, states, record chains, and checkpoints. `db pack` /
  `db unpack` give a single-file backup.
