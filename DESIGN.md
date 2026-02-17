# DESIGN

## 1. Core model

Canonical truth is immutable content-addressed data.

- Blobs (`BlobStore`): raw byte payloads under `blobs/`.
- Objects (`ObjectStore`): typed DAG-CBOR objects under `objects/`.
  - manifests
  - state manifests and segments
  - commits

All identities are hashes of canonical bytes plus domain separators.

## 2. Canonical encoding and hashing

- Hash algorithm: BLAKE3.
- Canonical serialization: DAG-CBOR (`serde_ipld_dagcbor`).
- Domain separators prevent cross-type collisions.

Hash formulas:

- `H_blob = blake3("blob:" || blob_bytes)`
- `H_manifest = blake3("manifest:" || dag_cbor(manifest))`
- `H_state_node = blake3("state_node:" || dag_cbor(state_obj))`
- `H_commit = blake3("commit:" || dag_cbor(commit))`
- `H_state_leaf = blake3("state_leaf:" || leaf_encoding)`
- `H_merkle_node = blake3("merkle_node:" || left_hash || right_hash)`

`src/canonical.rs` includes golden-byte tests that lock deterministic canonical bytes for selected structures.

## 3. State model (segmented persistent map)

State root points to:

```text
StateManifest {
  schema_version,
  segments: [newest ... oldest],
  segments_merkle_root
}
```

Each immutable segment:

```text
StateSegment {
  schema_version,
  entries: sorted unique (key -> value_hash | tombstone),
  merkle_root
}
```

Operations:

- `set(root, key, value)` appends one update segment.
- `del(root, key)` appends one tombstone segment.
- `get(root, key)` scans segments newest to oldest.
- `compact(root)` merges visible keys into one segment and prunes tombstones.

## 4. State proof model

`StateProof` carries a compact manifest commitment view, not full manifest payload:

- `manifest_schema_version`
- `manifest_segment_count`
- `manifest_segments_root`
- `scans[]` for the scanned prefix
- `outcome`

Each scan contains:

- `segment_hash`
- manifest inclusion proof for `segment_hash`
- segment merkle metadata (`segment_merkle_root`, `segment_leaf_count`)
- key proof (inclusion or non-inclusion)
- verdict

Verification flow:

1. Load manifest from `state_root`.
2. Validate commitment fields against loaded manifest.
3. Verify segment inclusion proofs in manifest segment merkle root.
4. Verify key proofs in each segment merkle root.
5. Enforce scan-prefix termination semantics.

Proof limitation (MVP): non-membership remains scan-prefix based, so proof size scales with scanned segments.

## 5. Commit graph and auth hooks

Commit schema:

```text
Commit {
  schema_version,
  parents,
  timestamp,
  author,
  message,
  state_root,
  manifests,
  signature?: CommitSignature
}
```

Extension hooks:

- `trait CommitSigner`
- `trait CommitVerifier`

`create_signed_commit` uses these hooks without forcing a specific crypto backend.

## 6. Crash safety and WAL recovery

- File writes use temp-file + rename.
- Mutable ops write structured WAL entries first.
- `Database::open` acquires recovery lock, migrates config, replays/rolls back pending WAL.
- Ref WAL entries are replayed.
- Interrupted immutable state mutation WAL entries are rolled back (discarded), because content-addressed objects are immutable.

## 7. Multi-process safety

- Ref writes acquire `refs/.refs.lock`.
- Recovery/migration acquires `meta/recovery.lock`.

This prevents concurrent mutation/recovery races.

## 8. Schema versioning and migration

- DB config has `schema_version` with migration path from legacy v1 format.
- Manifests include `schema_version` and migration helpers.
- State and commits include schema fields and migration defaults.

## 9. Verify-on-read integrity mode

`meta/config.json` includes `verify_on_read`.

When enabled:

- `BlobStore::get` re-hashes bytes and rejects mismatches.
- Typed `ObjectStore` reads re-hash with expected tag and reject mismatches.

## 10. Encryption at rest

Encryption is optional and configured through `EncryptionConfig`.

- Supported AEAD algorithms: `aes-256-gcm`, `chacha20-poly1305`
- KDF: `pbkdf2` (PBKDF2-HMAC-SHA256)
- Randomness source: OS CSPRNG via `getrandom`
- Payload metadata stores algorithm, KDF, salt, nonce, and iterations

Decryption failures are treated as authentication failures (wrong key or tampered ciphertext).

## 11. Derived search indexes (implemented)

Search indexes are derived artifacts stored under:

```text
index/<commit_hash>/search_index.json
```

They are rebuilt from commit manifests and are not canonical source of truth.

### 11.1 Build pipeline

`SearchIndexStore::build_for_head(commit, ...)`:

1. Load commit manifests.
2. Ingest `DocManifest` chunks as semantic documents.
3. Ingest `ChunkManifest` text + embeddings (if present).
4. Build semantic tables:
   - tokenized postings
   - per-document lengths
   - term document frequencies
   - average doc length
5. Persist JSON index and return an index version hash.

### 11.2 Semantic search

- Query mode: BM25-style scoring over chunk text.
- Tokenization: lowercase alphanumeric split.
- Retrieval: top-k by score.

### 11.3 Vector search

- Embeddings are read from chunk embedding blobs.
- Supported embedding blob formats: DAG-CBOR `Vec<f32>`/`Vec<f64>` and JSON float arrays.
- Similarity: cosine on matching-dimension vectors.
- Retrieval: top-k by score.

### 11.4 API surface

`src/index/mod.rs` provides:

- `SearchIndexStore` build/read/search methods
- `SearchHit` result type
- `trait IndexBuilder` compatibility hook

This keeps canonical storage minimal while providing native local semantic and vector search.
