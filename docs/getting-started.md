# Getting started

## Install

```bash
cargo install neleus-db
```

This installs `neleus-db` and `neleus-verify` (the offline audit-bundle
verifier). To build from source instead:

```bash
git clone https://github.com/auralshin/neleus-db
cd neleus-db
npm --prefix console ci && npm --prefix console run build   # optional: web console
cargo build --release                                       # binaries in target/release/
```

Without the console step, `serve` still runs the HTTP API but has no UI.

The rest of this page uses an alias:

```bash
alias ndb='neleus-db --db ./agent_db'
```

## 1. Initialize

```bash
ndb db init ./agent_db
```

Settings live in `agent_db/meta/config.json`. See [security.md](security.md)
for encryption and durability.

## 2. Ingest a document

```bash
ndb manifest put-doc --source policy.md --file policy.md \
    --chunk-size 512 --overlap 64 --doc-type policy --acl group:hr
# prints the manifest hash

ndb commit new --head main --author ingest --message "policy v1" --manifest <manifest-hash>
```

Metadata flags become search filters. A commit indexes its manifests.

## 3. Search

Modes: `semantic` (BM25), `vector` (HNSW), `hybrid` (both). Every search is
recorded on its head.

```bash
ndb search hybrid --head main --query "password reset policy" --acl group:hr --top-k 5
ndb search vector --head main --embedding-file query.json --top-k 5   # JSON or CBOR float array
ndb search semantic --head main --query "reset" --acl group:hr --at <commit-hash>
```

Chunks with an ACL tag only match callers that pass that tag with `--acl`.

## 4. Prove a hit and verify it offline

```bash
ndb proof chunk --head main --chunk <chunk-hash> --include-content --out hit.proof
ndb proof verify-chunk hit.proof
```

## 5. Sign commits and checkpoints

```bash
ndb key generate --out agent.key            # prints the public key
ndb commit new --head main --author agent --message "..." --sign-key agent.key
ndb checkpoint new --head main --sign-key agent.key
ndb checkpoint verify --head main --public-key <hex> --require-signatures
```

## 6. Session memory

```bash
ndb session append --head main --session-id s1 --role user --content "hi" --ttl-secs 3600
ndb session list --head main --session-id s1
ndb session gc --head main                  # remove expired turns
```

## 7. Serve over HTTP

```bash
ndb serve --open                            # http://127.0.0.1:7117/
```

On loopback, `serve` prints a temporary admin token and a `neleus://` connection
string for the SDKs. For apps and CI, mint a key:

```bash
ndb auth add-key --id ci --role writer      # token printed once
curl -H "Authorization: Bearer nlk_..." \
     -d '{"at":"main","query":"reset policy","filter":{"acl":["group:hr"]}}' \
     http://127.0.0.1:7117/v1/search
```

Binding a non-loopback address needs `--allow-remote` and a TLS proxy in front.
See [http-api.md](http-api.md) and [policy.md](policy.md).

## 8. Export an audit bundle

```bash
ndb audit export --head main --out q1.nelaudit --sign-key agent.key
neleus-verify q1.nelaudit --public-key <hex> --require-signature
```

## From Rust

```rust
use neleus_db::manifest::ChunkingSpec;
use neleus_db::{Engine, SearchFilter, SearchQuery, verify_chunk_proof};

let engine = Engine::open("./agent_db")?;
let spec = ChunkingSpec { method: "fixed".into(), chunk_size: 512, overlap: 64 };
let (_, commit) = engine.put_document("main", "policy.md", &std::fs::read("policy.md")?, spec, None, "ingest")?;
let q = SearchQuery::Hybrid { text: Some("reset policy"), embedding: None };
let hits = engine.search("main", None, q, 5, &SearchFilter::default(), None)?.hits;
verify_chunk_proof(&engine.prove(commit, hits[0].chunk_hash, true)?)?;
```

More in [../examples](../examples/README.md) and [concepts.md](concepts.md).
