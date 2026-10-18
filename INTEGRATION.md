# Integration guide

An integration does three things: ingest documents, search them (every search
is recorded on a head), and export proofs or audit bundles that verify offline.
See [docs/concepts.md](docs/concepts.md) for the model,
[docs/http-api.md](docs/http-api.md) for routes, and [docs/cli.md](docs/cli.md)
for commands.

neleus is one binary or an embedded library with no service dependencies.
Embeddings are yours: pass vectors to `vector`/`hybrid` search, or search text
only. `semantic` mode is BM25 keyword search. TLS is terminated by a proxy in
front of `serve`.

## Pick a path

| You have | Use |
|---|---|
| Rust, DB in process | `neleus_db::Engine` |
| Python, DB in process | [`sdk/python-native`](sdk/python-native) (PyO3) |
| Python, remote DB | [`sdk/python`](sdk/python) (HTTP, stdlib only) |
| TypeScript / Node 18+ / browser | [`@neleus/client`](sdk/typescript) |
| Rust, remote DB | [`neleus-client`](sdk/rust) |
| Anything else | the HTTP API |

## How searches are recorded

Every search through the server, the CLI, the SDKs, or `Engine::search` writes
a retrieval record (a `QueryManifest`) on the head it names. You do not record
or commit it yourself. The record holds the principal, query, the commit
searched, and every hit, plus a gapless `seq` and a `prev` link. Records live
under `refs/records/<head>`, not in the head's commit history.

To search a past commit, pass `commit` (HTTP) or `--at` (CLI). The search is
still recorded on the head, and the commit must be in that head's history.
Only `Engine::search_*_unrecorded` skips the record.

## Connect (HTTP SDKs)

```
neleus.connect("neleus://nlk_…@127.0.0.1:7117")     # Python
connect("neleus://nlk_…@127.0.0.1:7117")            # TypeScript
Client::connect("neleus://nlk_…@127.0.0.1:7117")    # Rust
```

Default port is 7117. With no argument, Python and TypeScript read
`NELEUS_URL`. `serve` on loopback prints a ready connection string with a
per-process bootstrap admin token. For durable keys:
`neleus-db --db ./db auth add-key --id app --role writer [--tenant acme]`.

Errors are `{ error, code, hint }`. Branch on `code` (`policy_violation`,
`unauthorized`, `forbidden`, `not_found`, `bad_request`, ...). Python raises
`neleus.PolicyViolation`, `neleus.Unauthorized`, and so on; TypeScript and
Rust errors carry `.code` and `.hint`.

## Python, in process

```python
import neleus_native as n

db = n.Neleus("./agent_db")                      # opens or initializes
db.put_document("main", "nda.txt", open("nda.txt").read())

hits = db.search("main", "indemnification terms", mode="hybrid",
                 top_k=3, principal="reviewer-v1")   # recorded on main
context = "\n\n".join(db.get_blob(h["chunk"]).decode() for h in hits)
# ... call your model with `context` ...

db.checkpoint("main")
proof = db.prove(hits[0]["commit"], hits[0]["chunk"])
assert db.verify_proof(proof)["valid"]
db.audit_export("main", "main.nelaudit")         # unsigned, full history
```

Build with `sdk/python-native/build.sh` or `maturin develop`.

## Python, HTTP

```python
import neleus

c = neleus.connect("neleus://nlk_…@127.0.0.1:7117")
c.put_document("main", "nda.txt", open("nda.txt").read())
res = c.search("main", query=question, top_k=3)
proof = c.prove(res["commit"], res["hits"][0]["chunk"])
assert c.verify(proof)["valid"]
```

Run capture stores a model call (prompt, retrieved chunks, output) as a
committed `RunManifest`:

```python
with neleus.run(url="neleus://nlk_…@127.0.0.1:7117", provider="anthropic",
                model="claude-sonnet-4-6", agent_id="reviewer-v1",
                subject="user-123") as run:
    run.prompt(question)
    run.retrieved_chunks([h["chunk"] for h in res["hits"]])
    run.output(call_model(question))
# commits on clean exit; run.abort() or an exception skips the commit
```

Over HTTP, `neleus.run` also takes `trace_id`, `parent_span` (the parent run's
manifest hash), and `delegated_from` to link runs across agent handoffs. `subject` tags
the run for [erasure](docs/design/retention-and-erasure.md). The recorded model
is the one you declare; neleus cannot attest which model actually ran.
`neleus.run(db=...)` uses a CLI subprocess per call instead of HTTP; it is slow
and meant for scripts.

## TypeScript

```ts
import { connect, withRun } from "@neleus/client";

const db = connect("neleus://nlk_…@127.0.0.1:7117");
const res = await db.search("main", { query: question, topK: 3 });
const context = (await Promise.all(res.hits.map((h) => db.chunkText(h.chunk)))).join("\n\n");

await withRun(db, { provider: "anthropic", model: "claude-sonnet-4-6", agentId: "reviewer" },
  async (run) => {
    run.prompt(question).retrievedChunks(res.hits.map((h) => h.chunk));
    await run.output(await callModel(context, question));
  });

const proof = await db.prove(res.commit, res.hits[0].chunk);
console.assert((await db.verify(proof)).valid);
```

## Rust, in process

```rust
use neleus_db::{Database, Engine, SearchFilter, SearchQuery};
use neleus_db::manifest::ChunkingSpec;

Database::init("./agent_db")?;                               // once
let engine = Engine::open("./agent_db")?;
engine.put_document("main", "nda.txt", &std::fs::read("nda.txt")?,
    ChunkingSpec { method: "fixed".into(), chunk_size: 512, overlap: 64 },
    None, "ingest")?;

let q = SearchQuery::Hybrid { text: Some("indemnification terms"), embedding: None };
let found = engine.search("main", None, q, 3, &SearchFilter::default(), Some("reviewer-v1"))?;
let text = engine.db().blob_store.get(found.hits[0].chunk_hash)?;

engine.checkpoints().create("main", None)?;
let proof = engine.prove(found.commit, found.hits[0].chunk_hash, true)?;
neleus_db::verify_chunk_proof(&proof)?;
```

To sign commits, call `engine.set_commit_signer` with an `Ed25519Signer`
(`Ed25519Signer::from_seed_file`, key from `neleus-db key generate --out k.key`).

## Rust, HTTP

```rust
use neleus_client::{Client, SearchOpts};

let c = Client::connect("neleus://nlk_…@127.0.0.1:7117")?;
let res = c.search("main", SearchOpts { query: Some("policy".into()), ..Default::default() })?;
let proof = c.prove(&res.commit, &res.hits[0].chunk, true, None)?;
assert!(c.verify(&proof)?.valid);
```

## Proofs and audit bundles

A **chunk proof** shows a chunk was in the corpus at a commit. It verifies with
`verify_chunk_proof`, `POST /v1/proofs/verify`, or
`neleus-db proof verify-chunk`. Without an anchor it only shows internal
consistency, so compare the commit hash with one you trust, or anchor it in a
checkpoint (`anchor_head` / `--anchor-head`).

An **audit bundle** carries a head's retrieval records for a time window and
verifies with the standalone `neleus-verify` binary (no database, no network):

```
neleus-db --db ./db key generate --out audit.key            # prints public key
neleus-db --db ./db checkpoint new --head main --sign-key audit.key
neleus-db --db ./db audit export --head main --from <unix> --to <unix> \
    --out q1.nelaudit --sign-key audit.key [--anchor <checkpoint>]
neleus-verify q1.nelaudit --public-key <hex> --require-signature [--anchor <checkpoint>]
```

Over HTTP, `POST /v1/audit/export` returns the bundle (TypeScript
`exportBundle`, Rust `export_bundle`). It is signed only if `serve` was started
with `--sign-key`. The same key then also signs the server's commits and
erasure records. Checkpoints made over HTTP are not signed.

Things to know:

- Make a checkpoint right before exporting. Records newer than the latest
  checkpoint are not pinned, so dropping them from the end is not detectable.
- `--public-key` checks the bundle signature and any checkpoint signatures, so
  sign both with the same key.
- An unsigned bundle detects corruption but not edits by the exporter.
- `--anchor` takes a checkpoint hash the auditor kept from earlier. The bundle
  must extend it, and records at or below its pin cannot be truncated or
  re-chained.

## Tenants

A key made with `--tenant acme` may only name heads under `acme/`, and its
searches are forced to `tenant=acme`. It cannot read raw blobs
(`GET /v1/blobs/…`, so TypeScript `chunkText` and Rust `blob_get` fail), and
its chunk proofs must name a `head` under its prefix, omit content, and prove
a commit in that head's history. In the SDKs, pass `head` and
`include_content=False` (Python), `prove(commit, chunk, false, head)`
(TypeScript), or `prove(commit, chunk, false, Some(head))` (Rust). See
[docs/security.md](docs/security.md).

## Operations

- Open the embedded engine once per process and reuse it.
- The server serializes writes with one lock. Searches do not take it, and
  concurrent searches on a head share one record update.
- Durability modes are in [docs/security.md](docs/security.md); write-time
  policies in [docs/policy.md](docs/policy.md).
