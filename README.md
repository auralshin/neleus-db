<div align="center">

# 🔱 Neleus DB

## Prove what your AI agent knew when it decided

neleus-db is a tamper-evident, content-addressed Merkle-DAG database for AI
agent memory, written in Rust. It runs hybrid retrieval (BM25 plus vectors),
git-like immutable versioning, and session memory, and every answer carries a
cryptographic receipt. Warm queries run in well under a millisecond, and any
hit can be turned into an offline-verifiable Merkle proof. The audit surface is
built in: signed audit export and a standalone verifier (`neleus-verify`) that
an auditor runs without Neleus.

[Get started](docs/getting-started.md) · [CLI](docs/cli.md) · [HTTP API](docs/http-api.md) · [Benchmarks](BENCHMARKS.md) · [Design](DESIGN.md) · [Report Bug](https://github.com/auralshin/neleus-db/issues/new?labels=bug)

</div>

---

## Why

Vector databases and agent-memory products are fast but trust-free: nothing
stops history from being rewritten, and nothing proves what an agent actually
retrieved. Audit logs are "trust me" artifacts. neleus-db makes the storage
layer itself the proof.

- **Content-addressed everything.** Blobs, manifests, commits, and state are
  BLAKE3-addressed immutable objects. Tampering changes the hash, and the hash
  is the identity.
- **Proof-carrying retrieval.** Any search hit `(commit, chunk)` becomes a
  self-contained bundle you can verify offline with nothing but BLAKE3 and a
  CBOR decoder (`proof chunk` / `proof verify-chunk`).
- **Resident engine.** BM25, HNSW, and metadata filters are served from
  in-memory caches over immutable segments. Warm point reads and BM25 search
  are faster than SQLite on the same machine ([numbers](BENCHMARKS.md)).
- **Local or hosted, one code path.** Embed the crate in-process, or run
  `neleus-db serve` for an authenticated multi-tenant HTTP API. Both use the
  same engine.

As of mid-2026 no shipping agent-memory product (Mem0, Zep, Supermemory, Letta,
Cognee) offers cryptographic tamper-evidence. See
[BENCHMARKS.md](BENCHMARKS.md#3-the-verifiability-gap).

## Capabilities

**Retrieval**
- Hybrid search: BM25 and HNSW vectors fused with reciprocal rank fusion
- Metadata filters: tenant, doc type, language, ACL tags, validity windows
- Time-travel: query any historical commit (`search --head <commit-hash>`)
- TTL and temporal validity (`valid_from`/`valid_to`/`expires_at`) as engine
  primitives
- Hierarchical retrieval via `SummaryManifest` (summaries indexed beside
  chunks, linked to their evidence)

**State and memory**
- Versioned KV with O(log n) Merkle membership and non-membership proofs
- Content-addressed prolly tree (Merkle B+-tree): canonical roots, ordered
  prefix scans, inline small values, blob-backed large values. Warm gets run
  under SQLite point-read latency.
- Episodic session memory with TTL (`session append/list/gc`)

**Verifiability**
- ed25519-signed commits (`key generate`, `commit new --sign-key`)
- Checkpoint chains: an append-only transparency log over each head
  (`checkpoint new/verify`). Publish the latest hash anywhere to externally
  anchor the whole history.
- Content-addressed query audit records (`search --audit`), sequence-chained
  per head so a record dropped from an export is detectable
- Offline chunk proofs spanning commit ancestry

**Operations**
- `neleus-db serve`: std-only HTTP server, API keys (BLAKE3-hashed,
  constant-time), role ladder reader/writer/admin, hard tenant partitioning
- Replication: `db push` / `db pull`, fast-forward only and content-addressed
  (no force-push; divergence is reported, not overwritten)
- Encryption at rest: AES-256-GCM or ChaCha20-Poly1305, Argon2id master key
- Durability: `os` (default, SQLite-WAL class) or `full` (fsync per write)
- Backup (`db pack/unpack`), GC, repack. Everything in `index/` is derived and
  rebuildable.

## Quick start

```bash
cargo build --release
alias ndb='./target/release/neleus-db --db ./agent_db'

ndb db init ./agent_db

# ingest with metadata; commits auto-index
ndb manifest put-doc --source policy.md --file policy.md \
    --chunk-size 512 --overlap 64 --doc-type policy --acl group:hr
ndb commit new --head main --author ingest --message "policy v1" --manifest <hash>

# hybrid search with filters + audit record
ndb search hybrid --head main --query "password reset policy" \
    --acl group:hr --audit

# prove a hit, verify offline
ndb proof chunk --head main --chunk <chunk-hash> --include-content --out hit.proof
ndb proof verify-chunk hit.proof

# signed commits + transparency log
ndb key generate --out agent.key
ndb commit new --head main --author agent --message "..." --sign-key agent.key
ndb checkpoint new --head main --sign-key agent.key
ndb checkpoint verify --head main --public-key <hex> --require-signatures

# session memory with TTL
ndb session append --head main --session-id s1 --role user --content "hi" --ttl-secs 3600
ndb session list --head main --session-id s1
```

### Server mode

```bash
ndb auth add-key --id ci --role admin            # token printed once
ndb serve --addr 127.0.0.1:7117                  # loopback; TLS-terminate in front for remote
curl -H "Authorization: Bearer nlk_..." -d '{"at":"main","query":"reset policy"}' \
     http://127.0.0.1:7117/v1/search
```

Tenant keys (`auth add-key --tenant acme`) are hard-partitioned: they can
only touch heads under `acme/`, every search is forced to their tenant
filter, and raw blob and replication endpoints are unreachable.

> **Note on scoring.** BM25 collection statistics are scoped to the caller's
> partition, so a tenant's scores do not reveal documents it cannot see, and a
> term appearing only in hidden documents looks absent. Vector-search *timing*
> can still depend on hidden data, because HNSW traversal crosses non-matching
> nodes to preserve recall. See
> [BENCHMARKS.md §5](BENCHMARKS.md#fixed-bm25-collection-statistics-are-now-tenant-scoped).

### Web console + policy enforcement

`serve` bundles a web console into the binary. One command, no Node, no CORS:

```bash
ndb serve --open                                 # boots engine + console at http://127.0.0.1:7117/
```

On loopback it mints a one-time bootstrap admin token, so localhost works
without setup. The console is the policy surface: the audit log, the proof
inspector, and the **policy** views.

Neleus enforces policy; it does not just store compliance reports. Declare
rules as code and the server refuses the write that would violate them:

```bash
ndb policy set policy.json    # e.g. require-encryption-at-rest / retention-floor / require-principal (enforce)
ndb policy eval               # score every rule against live state
ndb events list               # tamper-evident, hash-chained violation log
```

Violations append to a hash-chained event log, stream to the console's live
Monitor, and can fire a webhook. See [docs/policy.md](docs/policy.md).

### Replication

```bash
NELEUS_DB_TOKEN=nlk_... ndb db pull --remote http://primary:7117
NELEUS_DB_TOKEN=nlk_... ndb db push --remote http://replica:7117
```

Fast-forward only; checkpoint chains merge under the same rule.

## SDKs

Under `sdk/`. Pick by language and by whether the database is in-process or
remote.

| SDK | Transport | Use when |
|---|---|---|
| [`sdk/python-native`](sdk/python-native) | **Embedded** (PyO3) | the database runs *in* your Python process (fastest, no network) |
| [`sdk/python`](sdk/python) | HTTP / CLI | Python talking to a remote `serve` (stdlib-only) |
| [`sdk/typescript`](sdk/typescript) | HTTP (`fetch`) | Node 18+ or browser clients |
| [`sdk/rust`](sdk/rust) | HTTP (std-only) | Rust clients of a remote `serve` |

The Rust crate itself (`neleus_db::Engine`) is the embedded path for Rust.
Ingest, hybrid search, proofs and session append are in every SDK; the rest of
the surface is not yet uniform:

| | python | typescript | rust | python-native |
|---|---|---|---|---|
| ingest, search, prove, verify | yes | yes | yes | yes |
| session append | yes | yes | yes | yes |
| session list | yes | yes | yes | no |
| state get/set | yes | yes | no | no |
| checkpoints | yes | yes | yes | yes |
| run capture | yes | yes | yes | no |
| audit export | no | yes | yes | yes |
| blob get/put | put only | yes | yes | get only |

TypeScript is the most complete HTTP client. Anything missing is reachable over
the [HTTP API](docs/http-api.md) directly.

```python
# native, in-process
import neleus_native as n
db = n.Neleus("./agent_db")
_, commit = db.put_document("main", "kb.md", open("kb.md").read())
hits = db.search("main", "reset policy", mode="hybrid", top_k=5)
assert db.verify_proof(db.prove(commit, hits[0]["chunk"]))["valid"]
```

```ts
// TypeScript, over HTTP
import { connect } from "@neleus/client";
const c = connect("neleus://nlk_...@127.0.0.1:7117");
const res = await c.search("main", { query: "reset policy", audit: true });
const proof = await c.prove(res.commit, res.hits[0].chunk);
console.assert((await c.verify(proof)).valid);
```

The TypeScript, Rust and native SDKs each have a README and a test suite: the
Rust and TS suites spin up a server, the native suite runs in-process.
`sdk/python` is a single stdlib-only module with neither.

## Architecture

```text
canonical (immutable, verifiable)        serving (derived, fast, rebuildable)
─────────────────────────────────        ────────────────────────────────────
blobs/    content-addressed bytes        index/segments/  BM25 + HNSW + metadata
objects/  manifests, state, commits  →   index/heads/     segment set per commit
refs/     heads, staged state,           in-memory caches: segments, state,
          checkpoint chains                               blobs (byte-budgeted)
```

Hash domains: `blob:`, `manifest:`, `manifest_leaf:`, `state_node:`,
`state_level:`, `commit:`, `commit_payload:`, `checkpoint:`,
`checkpoint_payload:`, `checkpoint_leaf:`, `merkle_node:`, `merkle_root:`,
`index_segment:`. All are BLAKE3 over canonical DAG-CBOR, and golden-byte tests
lock the encodings.

The serving plane is never hashed into identity: delete `index/` and you lose
nothing but warm-up time.

## Security model

| Layer | Mechanism |
|---|---|
| At rest | AES-256-GCM / ChaCha20-Poly1305 per object; Argon2id (19 MiB, t=2) master key; per-object HKDF keys; key rotation |
| In transit | server is loopback-only unless `--allow-remote` plus keys; TLS terminates in front (no in-process TLS by design) |
| AuthN | `nlk_` bearer tokens, BLAKE3-hashed at rest, constant-time compare, instant revocation |
| AuthZ | reader < writer < admin; tenant keys hard-partitioned structurally; BM25 statistics partition-scoped |
| Tamper evidence | content addressing, signed commits, checkpoint chains, offline proofs |
| Memory hygiene | keys zeroized on drop; 0600 key files; secrets never logged or stored |
| Durability | `os` (crash-safe, fast) or `full` (power-loss durable) per database |

## Testing & benchmarks

```bash
cargo test            # 311 tests: determinism, proofs, recovery, tenancy,
                      # HNSW recall >= 0.90 vs exact oracle, end-to-end HTTP
cargo bench --bench compare_sql   # vs SQLite on your machine
cargo bench --bench scale         # 100k chunks, 1536d vectors, coalesced writes
cargo bench --bench state         # proof size + offline verification time
cargo bench --bench verifiability # chain scaling, cold audit, tenant leakage
```

See [BENCHMARKS.md](BENCHMARKS.md) for measured results and market context.

## Audit

Every audited retrieval becomes a signed, offline-verifiable record:

```bash
ndb audit export --head main --out q1.nelaudit --sign-key agent.key
neleus-verify q1.nelaudit --public-key <hex>       # offline, no Neleus needed
```

## Docs

- [INTEGRATION.md](INTEGRATION.md): wire neleus into an agent, the six-step flow in every language
- [docs/getting-started.md](docs/getting-started.md): zero to verifiable memory in one page
- [docs/concepts.md](docs/concepts.md): content addressing, commits, checkpoints, proofs, the two planes
- [docs/cli.md](docs/cli.md): every command, with flags
- [docs/http-api.md](docs/http-api.md): server endpoint reference, auth, CORS, tenancy
- [docs/security.md](docs/security.md): threat model and controls
- [DESIGN.md](DESIGN.md): Merkle model, storage planes, recovery
- [BENCHMARKS.md](BENCHMARKS.md): measured numbers and the verifiability gap
- [CONTRIBUTING.md](CONTRIBUTING.md): the byte-format rule and the test bar

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in this work
by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions. Contributions are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md).
