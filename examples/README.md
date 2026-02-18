# Examples

This directory contains runnable examples for common `neleus-db` workflows.

## Run examples

```bash
cargo run --example 01_basic_blob_storage
cargo run --example 02_state_and_commits
cargo run --example 03_document_chunking
cargo run --example 04_provenance_tracking
cargo run --example 05_state_proofs
```

## Example list

### 01) Basic blob storage
Shows immutable blob put/get and hash-based deduplication.

### 02) State and commits
Shows versioned state roots, Git-like commits, head updates, and time-travel reads.

### 03) Document chunking
Shows deterministic fixed chunking via `DocManifest` and retrieving chunk blobs.

### 04) Provenance tracking
Shows claim/evidence tracking with `ProvenanceRecord` and `ProvenanceManifest`.

### 05) State proofs
Shows membership, non-membership, and deletion proofs using `StateStore::proof` and `verify_proof`.

## Notes

- Each example uses `tempfile::TempDir` and is self-contained.
- Examples target the current public API (`Database::init` + `Database::open`).
