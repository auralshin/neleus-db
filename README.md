<div align="center">
  <p align="center">
    <a href="#contributors"><img src="https://img.shields.io/badge/contributors-1-brightgreen?style=flat-square" alt="Contributors"></a>
    <a href="https://github.com/auralshin/neleus-db/network/members"><img src="https://img.shields.io/github/forks/auralshin/neleus-db?style=flat-square" alt="Forks"></a>
    <a href="https://github.com/auralshin/neleus-db/stargazers"><img src="https://img.shields.io/github/stars/auralshin/neleus-db?style=flat-square" alt="Stars"></a>
    <a href="https://github.com/auralshin/neleus-db/issues"><img src="https://img.shields.io/github/issues/auralshin/neleus-db?style=flat-square" alt="Issues"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  </p>
  
# 🔱 Neleus DB

## Local-first Merkle-DAG database for AI agents, reproducible runs, and verifiable state

  A high-performance, content-addressed database designed for AI agent workflows with cryptographic proofs and immutable versioning.

  [Examples](examples/) · [Report Bug](https://github.com/auralshin/neleus-db/issues/new?labels=bug) · [Request Feature](https://github.com/auralshin/neleus-db/issues/new?labels=feature)
</div>

---

## Contents

- [Why neleus-db](#why-neleus-db)
- [Who should use this](#who-should-use-this)
- [Features](#features)
- [Architecture at a glance](#architecture-at-a-glance)
- [Installation](#installation)
- [Examples](#examples)
- [Quick start](#quick-start)
- [CLI](#cli)
- [Public Rust API](#public-rust-api)
- [Data layout](#data-layout)
- [Integrity and determinism](#integrity-and-determinism)
- [Reliability and security](#reliability-and-security)
- [Testing](#testing)
- [Integration guide](#integration-guide)
- [Design document](#design-document)
- [Contributing](#contributing)
- [License](#license)

## Why neleus-db

AI agent systems need more than a key-value store:

- deterministic replay from immutable inputs
- versioned state snapshots with commit history
- integrity proofs for auditability
- local operation without network dependencies

`neleus-db` is built around those guarantees.

## Who should use this

- teams building agent runtimes or orchestrators
- local/private RAG systems that need provenance
- products requiring tamper-evident run history
- developers who want Git-like history for agent state

## Features

- Content-addressed blob and object storage (`blake3`)
- Strict canonical object encoding (DAG-CBOR) with golden-byte tests
- Versioned segmented state store with Merkle commitments
- Membership and non-membership state proofs
- Git-like commit graph (`parents`, `author`, `message`, `state_root`, `manifests`)
- WAL + atomic file writes + automatic WAL recovery on open
- Lock-file protection for multi-process mutable operations
- Optional verify-on-read integrity checks
- Encryption at rest (AES-256-GCM / ChaCha20-Poly1305 + PBKDF2-HMAC-SHA256)
- Native semantic and vector search as rebuildable derived indexes

## Architecture at a glance

```text
Immutable canonical layer:
  blobs/   -> raw bytes
  objects/ -> canonical manifests, state objects, commits

Mutable pointers:
  refs/heads/*  -> commit hashes
  refs/states/* -> staged state roots

Derived/rebuildable layer:
  index/<commit_hash>/search_index.json

Reliability:
  wal/*.wal
  meta/config.json
```

## Installation

```bash
git clone https://github.com/auralshin/neleus-db
cd neleus-db
cargo build --release
```

## Examples

See the [examples/](examples/) directory for practical code demonstrating common patterns:

- **[01_basic_blob_storage.rs](examples/01_basic_blob_storage.rs)** - Content-addressed storage and deduplication
- **[02_state_and_commits.rs](examples/02_state_and_commits.rs)** - Versioned state with Git-like history
- **[03_document_chunking.rs](examples/03_document_chunking.rs)** - Deterministic document chunking and manifests
- **[04_provenance_tracking.rs](examples/04_provenance_tracking.rs)** - Evidence chains and confidence scoring
- **[05_state_proofs.rs](examples/05_state_proofs.rs)** - Cryptographic proof generation and verification

Run any example:

```bash
cargo run --example 01_basic_blob_storage
```

## Quick start

```bash
# 1) initialize DB
cargo run -- db init /tmp/neleus_db

# 2) add a blob
cargo run -- --db /tmp/neleus_db blob put /path/to/file.txt

# 3) create a document manifest + deterministic chunks
cargo run -- --db /tmp/neleus_db manifest put-doc \
  --source local_file \
  --file /path/to/file.txt \
  --chunk-size 512 \
  --overlap 64

# 4) update versioned state
cargo run -- --db /tmp/neleus_db state set main 6b6579 /path/to/value.bin --key-encoding hex

# 5) commit snapshot
cargo run -- --db /tmp/neleus_db commit new \
  --head main \
  --author agent1 \
  --message "initial snapshot" \
  --manifest <manifest_hash>

# 6) build and query derived search indexes
cargo run -- --db /tmp/neleus_db index build --head main
cargo run -- --db /tmp/neleus_db search semantic --head main --query "systems programming" --top-k 5
cargo run -- --db /tmp/neleus_db search vector --head main --embedding-file /path/to/query_embedding.json --top-k 5

# 7) generate and verify state proof
cargo run -- --db /tmp/neleus_db proof state main 6b6579 --key-encoding hex
```

## CLI

- `db init <path>`
- `blob put <file>`
- `blob get <hash> <out_file>`
- `manifest put-doc --source ... --file ... --chunk-size ... [--overlap ...]`
- `manifest put-run --model ... --prompt-file ... --io-hashes in:<hash> --io-hashes out:<hash>`
- `state set <head> <key> <value-file> [--key-encoding utf8|hex|base64]`
- `state get <head> <key> [--key-encoding utf8|hex|base64] [--out-file <path>]`
- `state del <head> <key> [--key-encoding utf8|hex|base64]`
- `state compact <head>`
- `commit new --head <name> --author <id> --message <text> [--manifest <hash> ...]`
- `index build --head <name>`
- `search semantic --head <name> (--query <text> | --query-file <path>) [--top-k <n>]`
- `search vector --head <name> --embedding-file <path> [--top-k <n>]`
- `log <head>`
- `proof state <head> <key> [--key-encoding utf8|hex|base64]`

Global flags:

- `--db <path>` (default: `./neleus_db`)
- `--json` machine-readable output

## Public Rust API

- `hash` - `Hash`, domain-separated hashing helpers
- `blob_store` - immutable content-addressed blobs
- `manifest` - typed manifests + deterministic chunking
- `state` - segmented persistent KV + proofs + compaction
- `commit` - commit objects + signing/verifier hooks
- `refs` - atomic refs and staged roots
- `db` - open/init, schema migration, WAL recovery orchestration
- `index` - derived semantic/vector index build and query

## Data layout

```text
<db_root>/
  blobs/aa/bb/<fullhash>
  objects/cc/dd/<fullhash>
  refs/heads/<name>
  refs/states/<name>
  index/<commit_hash>/search_index.json
  wal/*.wal
  meta/config.json
```

## Integrity and determinism

Hash domains:

- `H_blob = blake3("blob:" || bytes)`
- `H_manifest = blake3("manifest:" || dag_cbor_bytes)`
- `H_state_node = blake3("state_node:" || dag_cbor_bytes)`
- `H_commit = blake3("commit:" || dag_cbor_bytes)`
- `H_state_leaf = blake3("state_leaf:" || leaf_encoding)`
- `H_merkle_node = blake3("merkle_node:" || left || right)`

Canonical encoding:

- DAG-CBOR via `serde_ipld_dagcbor`
- deterministic bytes locked with golden tests in `src/canonical.rs`

## Reliability and security

- atomic temp-write + rename for persistent files
- structured WAL with replay/rollback during `Database::open`
- lock files for ref/state mutation safety across processes
- optional verify-on-read mode for blobs and typed objects
- authenticated encryption support for persisted payloads

## Testing

```bash
cargo test
```

The suite covers determinism, state semantics, proof verification/tampering, WAL recovery, integrity checks, compaction behavior, and CLI-facing flows.

## Integration guide

See `INTEGRATION.md` for Rust embedding patterns and CLI-based integration examples for TypeScript/JavaScript, Go, and Python.

## Design document

See `DESIGN.md` for details on Merkle model, proof format, and recovery behavior.

## Contributing

1. Open an issue describing the behavior or change.
2. Add tests with the change.
3. Keep object encoding/hash behavior backward compatible unless schema migration is included.

## License

MIT
