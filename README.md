<div align="center">
  <p align="center">
    <a href="#contributors"><img src="https://img.shields.io/badge/contributors-1-brightgreen?style=flat-square" alt="Contributors"></a>
    <a href="https://github.com/auralshin/neleus-db/network/members"><img src="https://img.shields.io/github/forks/auralshin/neleus-db?style=flat-square" alt="Forks"></a>
    <a href="https://github.com/auralshin/neleus-db/stargazers"><img src="https://img.shields.io/github/stars/auralshin/neleus-db?style=flat-square" alt="Stars"></a>
    <a href="https://github.com/auralshin/neleus-db/issues"><img src="https://img.shields.io/github/issues/auralshin/neleus-db?style=flat-square" alt="Issues"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  </p>
  
# 🔱 Neleus DB

## Verifiable memory and audit trails for AI agents

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
- [Python SDK](#python-sdk)
- [Integration guide](#integration-guide)
- [Design document](#design-document)
- [Contributing](#contributing)
- [License](#license)

## Why neleus-db

AI agent systems need more than a key-value store:

- auditable, state-replayable runs from immutable content-addressed inputs
- versioned state snapshots with commit history
- integrity proofs for every claim and retrieved chunk
- local operation without network dependencies

`neleus-db` is built around those guarantees.

> **On reproducibility:** neleus-db captures all inputs, retrieved context, and provider
> metadata needed for replay. Because hosted LLMs are non-deterministic and may change
> over time, runs are *auditable and state-replayable* rather than bit-for-bit reproducible.
> Equivalent outputs require equivalent model, parameters, and runtime conditions.

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
- **`RunManifest`** — captures provider, model, parameters, system prompt, inputs, outputs, and retrieved RAG chunks in one signed, Merkle-linked record
- **`ProvenanceRecord`** — agent claims with evidence, confidence scores, and `RunManifest` back-links
- WAL + atomic file writes + automatic WAL recovery on open
- Lock-file protection for multi-process mutable operations
- Optional verify-on-read integrity checks
- Encryption at rest for blobs and objects (AES-256-GCM / ChaCha20-Poly1305 + PBKDF2-HMAC-SHA256)
- Native semantic and vector search as rebuildable derived indexes
- **Python SDK** — `with neleus.run(...) as run:` context manager for zero-friction agent auditing

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

Storage maintenance:

- `db repack` — consolidate loose blobs/objects into pack files (reclaims per-file disk/inode overhead; crash-safe)
- `db packs` — list the pack files under `blobs/` and `objects/`
- `db gc [--prune] [--grace-secs <n>]` — reclaim objects unreachable from any ref; **dry-run by default**, `--prune` deletes. `--grace-secs` (default `3600`) protects objects modified that recently, so in-flight writes aren't swept.

Backup and transport (single self-contained file):

- `db pack <out> [--compress]` — export the whole DB to one file; `--compress` zstd-frames the stream
- `db unpack <input> [--force] [--verify-only]` — restore a DB from a pack; `--verify-only` checks integrity/structure without writing
- `db reencrypt [--new-password-env <VAR>]` — rotate the encryption key

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
- `db` - open/init, schema migration, WAL recovery orchestration, `repack`
- `index` - derived semantic/vector index build and query
- `packstore` - loose-object consolidation into pack files + pack-aware reads
- `gc` - reachability mark-and-sweep (fail-closed) over commits, state, and manifests
- `pack` - single-file whole-DB backup/restore with integrity footer

## Data layout

```text
<db_root>/
  blobs/aa/bb/<fullhash>          # loose objects (sharded by hash prefix)
  blobs/pack/pack-<id>.{pack,idx} # consolidated objects after `db repack`
  objects/cc/dd/<fullhash>
  objects/pack/pack-<id>.{pack,idx}
  refs/heads/<name>
  refs/states/<name>
  index/<commit_hash>/search_index.json
  wal/*.wal
  meta/config.json
```

Reads check the loose path first, then fall back to packs. `db repack` moves
loose objects into a pack and removes the loose copies; `db gc --prune` drops
objects unreachable from any ref (sweeping loose files and rewriting packs).
Both store the verbatim on-disk bytes, so packing/GC need no encryption password.

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

When encryption is enabled, **blobs and objects** are encrypted at rest with the configured
algorithm (AES-256-GCM or ChaCha20-Poly1305). WAL files, search indexes, metadata, and key
paths have separate leakage considerations — review the security notes before using this with
sensitive data in regulated environments.

To enable encryption, set `meta/config.json` with an enabled encryption block and provide
`NELEUS_DB_ENCRYPTION_PASSWORD` when running the CLI.

Example config snippet:

```json
{
  "schema_version": 3,
  "hashing": "blake3",
  "verify_on_read": true,
  "encryption": {
    "enabled": true,
    "algorithm": "aes-256-gcm",
    "kdf_iterations": 600000
  }
}
```

`master_salt` is generated automatically on the first open of an encryption-enabled database and added to `config.json`. Do not edit or rotate it manually — every existing ciphertext on disk depends on it. Rotate the *password* via `Database::rotate_encryption_key` instead. The AEAD parameters (key size, nonce size, per-blob salt size) are not user-configurable; they are fixed by the algorithm choice.

## Testing

```bash
cargo test
```

The suite covers determinism, state semantics, proof verification/tampering, WAL recovery, integrity checks, compaction behavior, and CLI-facing flows.

## Python SDK

Copy `sdk/python/neleus.py` alongside your project and add the neleus-db binary to `PATH`:

```python
import neleus

with neleus.run(
    db="./neleus_db",
    provider="anthropic",
    model="claude-sonnet-4-6",
    agent_id="policy-reviewer-v1",
    model_parameters={"max_tokens": 1024, "temperature": 0.0},
) as run:
    run.system_prompt("You are a policy analyst.")
    run.prompt(user_question)
    run.retrieved_chunks(chunk_hashes)   # RAG audit link

    response = anthropic_client.messages.create(...)

    run.output(response.content[0].text)
# auto-commits here — every input, chunk, and output is content-addressed
```

See [`examples/06_claude_run.py`](examples/06_claude_run.py) for a full working example.

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
