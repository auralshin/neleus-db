# neleus-db

A local-first, content-addressed database for AI agent memory, written in Rust.

Every search an agent runs is recorded, and any result can be turned into a
proof that someone else can check offline. You can show what an agent
retrieved, from which version of the data, and that the history was not
rewritten afterwards.

[Getting started](docs/getting-started.md) · [CLI](docs/cli.md) · [HTTP API](docs/http-api.md) · [Design](DESIGN.md) · [Benchmarks](BENCHMARKS.md)

## Features

- Hybrid retrieval: BM25 and HNSW vectors, fused with reciprocal rank fusion,
  with tenant, doc type, language, ACL, and validity-window filters.
- Immutable history: blobs, manifests, state, and commits are BLAKE3-addressed
  objects. Search any past commit with `--at`.
- Recorded retrieval: every search appends to a hash-linked audit chain.
- Offline proofs: state proofs, chunk proofs, and signed audit bundles, checked
  by the standalone `neleus-verify` binary.
- Checkpoint log: signed, append-only checkpoints over a head's history.
- HTTP server: `serve` with API keys, reader/writer/admin roles, tenant
  isolation, and a bundled web console.
- Policy engine: rules checked at write time, with a tamper-evident event log.
- Also: session memory with TTL, subject erasure, encryption at rest,
  replication (`db push` / `db pull`).

## Install

```bash
cargo install neleus-db      # installs neleus-db and neleus-verify
```

Or build from source with `cargo build --release`. See
[getting started](docs/getting-started.md) for the web console build.

## Usage

```bash
neleus-db db init ./agent_db
alias ndb='neleus-db --db ./agent_db'

ndb manifest put-doc --source policy.md --file policy.md --chunk-size 512   # prints manifest hash
ndb commit new --head main --author me --message "add policy" --manifest <manifest-hash>
ndb search hybrid --head main --query "password reset"                       # recorded on main

ndb proof chunk --head main --chunk <chunk-hash> --include-content --out hit.proof
ndb proof verify-chunk hit.proof

ndb serve --open     # HTTP API and console at http://127.0.0.1:7117/
```

From Rust:

```rust
use neleus_db::manifest::ChunkingSpec;
use neleus_db::{Engine, SearchFilter, SearchQuery, verify_chunk_proof};

let engine = Engine::open("./agent_db")?;
let spec = ChunkingSpec { method: "fixed".into(), chunk_size: 512, overlap: 64 };
let (_, commit) = engine.put_document("main", "policy.md", &std::fs::read("policy.md")?, spec, None, "me")?;
let q = SearchQuery::Hybrid { text: Some("password reset"), embedding: None };
let hits = engine.search("main", None, q, 5, &SearchFilter::default(), None)?.hits;
verify_chunk_proof(&engine.prove(commit, hits[0].chunk_hash, true)?)?;
```

## SDKs

In [`sdk/`](sdk): [`python-native`](sdk/python-native) (embedded, PyO3),
[`python`](sdk/python) (HTTP, stdlib only), [`typescript`](sdk/typescript)
(HTTP), and [`rust`](sdk/rust) (HTTP). See [INTEGRATION.md](INTEGRATION.md).

## Docs

- [docs/](docs/README.md): getting started, concepts, CLI, HTTP API, policy, security
- [DESIGN.md](DESIGN.md): data model, storage, recovery
- [BENCHMARKS.md](BENCHMARKS.md): measured numbers
- [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option.
