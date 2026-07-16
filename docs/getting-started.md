# Getting started

Zero to verifiable agent memory. Every command here is real; copy them.

## Build

```bash
git clone https://github.com/auralshin/neleus-db
cd neleus-db
cargo build --release
```

Two binaries land in `target/release/`: `neleus-db` (the database + server)
and `neleus-verify` (the standalone audit-bundle verifier you hand an
auditor). Put them on your `PATH`, or alias for the rest of this page:

```bash
alias ndb='./target/release/neleus-db --db ./agent_db'
```

## 1. Initialize

```bash
ndb db init ./agent_db
```

This creates the on-disk layout (`blobs/ objects/ refs/ index/ wal/ meta/`)
and writes `meta/config.json`. Encryption, durability, and retention are
config knobs — see [security.md](security.md).

## 2. Ingest a document

`manifest put-doc` chunks a file, content-addresses every chunk, and writes a
`DocManifest`. Metadata flags (tenant, doc type, ACL, validity window) attach
to every chunk and become retrieval filters.

```bash
ndb manifest put-doc --source policy.md --file policy.md \
    --chunk-size 512 --overlap 64 --doc-type policy --acl group:hr
# -> { "manifest_hash": "9a3f…" }
```

A manifest is inert until a commit references it. Commits are the unit of
history and the thing you can prove against:

```bash
ndb commit new --head main --author ingest --message "policy v1" --manifest 9a3f…
```

The commit auto-indexes (BM25 + HNSW + metadata columns) so the next query is
warm.

## 3. Search

Three modes — `semantic` (BM25), `vector` (HNSW), `hybrid` (both, RRF-fused).
Filters narrow by metadata; `--audit` records a content-addressed
`QueryManifest` of exactly what came back.

```bash
ndb search hybrid --head main --query "password reset policy" \
    --acl group:hr --top-k 5 --audit
```

Vector and hybrid need an embedding file (a JSON or CBOR float array):

```bash
ndb search vector --head main --embedding-file query.json --top-k 5
```

## 4. Prove a hit, verify it offline

Any returned `chunk` hash plus the `commit` it ran against produces a
self-contained proof bundle. The verifier needs only BLAKE3 + a CBOR
decoder — no database:

```bash
ndb proof chunk --head main --chunk <chunk-hash> --include-content --out hit.proof
ndb proof verify-chunk hit.proof
# -> VALID: chunk … was retrievable at commit … (anchored by a doc manifest)
```

## 5. Sign history and anchor it

Generate an ed25519 key, sign commits with it, and append checkpoints — an
append-only hash chain that makes history rewrites detectable:

```bash
ndb key generate --out agent.key            # prints the public key
ndb commit new --head main --author agent --message "..." --sign-key agent.key
ndb checkpoint new --head main --sign-key agent.key
ndb checkpoint verify --head main --public-key <hex> --require-signatures
```

## 6. Session memory

Episodic turns with TTL, living in the state store (so they inherit proofs
and history):

```bash
ndb session append --head main --session-id s1 --role user --content "hi" --ttl-secs 3600
ndb session list --head main --session-id s1
ndb session gc --head main                  # drop expired (honors retention floor)
```

## 7. Serve it

The same engine over HTTP, with the web console bundled in. On loopback a
bootstrap admin token is minted automatically, so this just works:

```bash
ndb serve --open                            # console at http://127.0.0.1:7117/
```

`serve` prints a `neleus://<token>@127.0.0.1:7117` connection string to paste
into any SDK. For apps and CI, mint a durable key instead:

```bash
ndb auth add-key --id ci --role writer      # token printed once
curl -H "Authorization: Bearer nlk_..." \
     -d '{"at":"main","query":"reset policy"}' \
     http://127.0.0.1:7117/v1/search
```

Non-loopback binds need `--allow-remote` and minted keys, with TLS terminated in
front. See [http-api.md](http-api.md) for every route and
[policy.md](policy.md) for monitoring and write-time enforcement.

## 8. Audit evidence

Audit records accumulate as you serve `--audit` queries. Export a period as a
signed bundle and let an auditor verify it without you:

```bash
ndb audit export --head main --out q1.nelaudit --sign-key agent.key
neleus-verify q1.nelaudit --public-key <hex> --require-signature
```

## From Rust

The crate is embeddable like SQLite. The high-level entry point is `Engine`:

```rust
use neleus_db::{Engine, SearchFilter};
use neleus_db::manifest::ChunkingSpec;

let engine = Engine::open("./agent_db")?;          // open once, query many
let (_manifest, commit) = engine.put_document(
    "main", "policy.md", std::fs::read("policy.md")?.as_slice(),
    ChunkingSpec { method: "fixed".into(), chunk_size: 512, overlap: 64 },
    None, "ingest",
)?;
let hits = engine.search_hybrid(commit, Some("reset policy"), None, 5, &SearchFilter::default())?;
let proof = engine.prove(commit, hits[0].chunk_hash, true)?;
assert!(neleus_db::verify_chunk_proof(&proof).is_ok());
```

See `examples/` for runnable programs and [concepts.md](concepts.md) for the
model underneath.
