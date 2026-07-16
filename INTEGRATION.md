# Integration guide

## What a neleus integration produces

Wiring neleus into an agent gives you three things:

1. **Fast hybrid retrieval** — BM25 + vector, fused, in the hundreds of
   microseconds in-process.
2. **A tamper-evident audit trail** — every retrieval your agent makes is
   recorded, committed, and chained. History rewrites are detectable.
3. **An exportable proof bundle** — hand it to an auditor; they verify it
   offline with `neleus-verify`, no dependency on you or on neleus's
   infrastructure.

The integration is the same six steps in every language:

```
Ingest → Retrieve → Run → Commit → Prove
                              └─ (optional) Claim a ProvenanceRecord
```

| Step | Produces | Why it matters |
|---|---|---|
| **Ingest** | `DocManifest` + chunk hashes in content-addressed storage | the corpus the agent retrieves from |
| **Retrieve** | ranked `(chunk_hash, score)` list + an optional audit record | the hashes are what prove what the agent saw |
| **Run** | a `RunManifest` linking prompt, retrieved chunks, and output | closes the audit loop: retrieval → model call |
| **Commit** | a commit, signed into the checkpoint chain | tamper-evident and time-stamped |
| **Prove** | a self-contained proof bundle | the artifact a regulator or auditor receives |

The rest of this guide shows how to execute those steps in each language.
Read [docs/concepts.md](docs/concepts.md) for the model underneath.

## Requirements

neleus is a single static binary (or an embedded library). It has **no runtime
service dependencies** — no separate database, message broker, or model server.

| | Minimum |
|---|---|
| **Rust toolchain** | stable, edition 2024 (`cargo build`). Needed only to build from source; a released binary needs none. |
| **OS / arch** | Linux, macOS, or Windows; 64-bit. |
| **External services** | none. No async runtime, no in-process TLS, no Ollama/embedding server. |
| **Embeddings** | caller-supplied — neleus does not bundle or call an embedding model. Pass vectors to vector/hybrid search; omit them to run BM25 only. |
| **Node / npm** | only to rebuild the web console (`npm --prefix console ci && npm --prefix console run build`). The `--no-default-features` build and the HTTP API need no Node. |
| **TLS** | terminated by a front proxy (Caddy/nginx); the server itself speaks plain HTTP. |
| **Disk / memory** | scales with the corpus; the index and content-addressed store live on local disk. No fixed floor. |

## Which integration mode

| You are building in… | Use | Latency class |
|---|---|---|
| **Rust** | the `neleus_db::Engine` library, in-process | µs reads, sub-ms writes |
| **Python**, DB in your process | the [native PyO3 binding](sdk/python-native) | µs reads (direct FFI) |
| **Python**, DB elsewhere | the [HTTP client](sdk/python) | ~1 ms over loopback |
| **TypeScript / Node / browser** | the [`@neleus/client`](sdk/typescript) HTTP SDK | ~1 ms over loopback |
| **Rust**, DB elsewhere | the [`neleus-client`](sdk/rust) HTTP SDK | ~1 ms over loopback |
| **Go / other** | the HTTP API directly ([docs/http-api.md](docs/http-api.md)) | ~1 ms over loopback |

For the hosted mode, run one `neleus-db serve` and point the HTTP SDKs at it.
For the embedded mode (Rust library or PyO3), there is no server and no
network — calls are direct.

## Connect

The HTTP SDKs take one connection string, `neleus://[token@]host[:port]`
(default port 7117; `neleuss://` for TLS):

```
neleus.connect("neleus://nlk_…@127.0.0.1:7117")     # Python
connect("neleus://nlk_…@127.0.0.1:7117")            # TypeScript
Client::connect("neleus://nlk_…@127.0.0.1:7117")    # Rust
```

Set `NELEUS_URL` and call `connect()` with no argument to read it from the
environment. `serve` prints the ready-to-paste string on startup.

`serve` also bundles the web console at `/`. On a loopback bind it mints a
bootstrap admin token and injects it into the page, so `neleus-db serve --open`
gives a working console with no key setup. For apps and CI, mint a durable key:
`neleus-db auth add-key --id app --role writer`.

Errors come back as `{ error, code, hint }`. Clients branch on the stable
`code` — `policy_violation`, `unauthorized`, `forbidden`, `not_found`,
`bad_request` — and `hint` says how to fix it. Python raises typed exceptions
(`neleus.PolicyViolation`, `neleus.Unauthorized`, …); the TS and Rust errors
carry `.code` and `.hint`.

## The complete flow, end to end

This is a full agent turn — retrieve, call the model, record, commit, prove,
verify — using the native Python binding (in-process). Build it with
`sdk/python-native/build.sh` (or `maturin develop`), then:

```python
import neleus_native as n
import anthropic

db = n.Neleus("./agent_db")
llm = anthropic.Anthropic()

# Ingest a document once (idempotent: identical content dedups).
db.put_document("main", "NDA-template-v3.pdf",
                open("nda.txt").read(), chunk_size=512, overlap=64)

def agent_turn(question: str) -> str:
    # 1. Retrieve BEFORE the model call — this is what the agent knew.
    hits = db.search("main", question, mode="hybrid", top_k=3)
    context = "\n\n".join(db.get_blob(h["chunk"]).decode() for h in hits)

    # 2. Call the model with the retrieved context.
    reply = llm.messages.create(
        model="claude-sonnet-4-6", max_tokens=512,
        messages=[{"role": "user",
                   "content": f"Context:\n{context}\n\nQuestion: {question}"}],
    ).content[0].text

    # 3. Record the retrieval as an audit manifest, then commit it.
    audit = db.record_query("main", question, top_k=3, principal="contract-reviewer-v1")
    commit = db.commit("main", f"answer: {question[:40]}", manifests=[audit])

    # 4. Anchor the commit in the signed transparency chain.
    db.checkpoint("main")
    return reply, commit, hits[0]["chunk"]

answer, commit, top_chunk = agent_turn("What are the indemnification terms?")

# 5. Prove the top retrieved chunk was in scope at that commit — and verify it.
proof = db.prove(commit, top_chunk)            # bytes: a self-contained bundle
verdict = db.verify_proof(proof)               # {"valid": True, "anchor": "doc"}
assert verdict["valid"]
```

What you now hold:

- The answer is **content-addressed** (chunk hashes are immutable),
  **committed** (in the signed checkpoint chain), **time-stamped**, and
  **attributed** (the principal is in the audit record).
- `proof` proves one chunk was retrievable at `commit`. It is self-contained
  — every link is a hash equation over bytes it carries — so it verifies with
  nothing but BLAKE3 + a CBOR decoder (`db.verify_proof`, or
  `neleus-db proof verify-chunk`).

To hand an **auditor** a whole period rather than one chunk, export a bundle —
it carries the audit records, the commit ancestry, and the signed checkpoint
chain, and verifies offline with the standalone `neleus-verify` binary (no
neleus install, no network):

```
$ neleus-db audit export --head main --from <unix> --to <unix> \
      --out 2026-q1.nelaudit --sign-key agent.key
$ neleus-verify 2026-q1.nelaudit --public-key <hex> --require-signature
VERIFIED: 14382 retrievals on head 'main', signed by ed25519:a3f9… —
          chain intact across 891 commits, 891 checkpoints (891 signed)
```

From the SDK: `db.audit_export("main", "2026-q1.nelaudit")`.

## Rust (embedded)

The fastest path — the engine runs in your process.

```toml
[dependencies]
neleus-db = { path = "path/to/neleus-db" }
anyhow = "1"
```

```rust
use neleus_db::{Engine, SearchFilter};
use neleus_db::manifest::ChunkingSpec;

let engine = Engine::open("./agent_db")?;                    // open once

// Ingest
let (_doc, commit) = engine.put_document(
    "main", "nda.txt", std::fs::read("nda.txt")?.as_slice(),
    ChunkingSpec { method: "fixed".into(), chunk_size: 512, overlap: 64 },
    None, "ingest",
)?;

// Retrieve (build context from full chunk text, not the preview)
let hits = engine.search_hybrid(commit, Some("indemnification terms"), None, 3, &SearchFilter::default())?;
let context: String = hits.iter()
    .map(|h| String::from_utf8_lossy(&engine.db().blob_store.get(h.chunk_hash).unwrap()).into_owned())
    .collect::<Vec<_>>().join("\n\n");

// … call your model with `context` …

// Record + commit + checkpoint
let audit = engine.record_query(commit, "hybrid", Some("indemnification terms"),
    None, 3, &SearchFilter::default(), Some("reviewer-v1"), &hits)?;
let answered = engine.commit("main", "reviewer-v1", "answered", vec![audit])?;
engine.checkpoints().create("main", None)?;

// Prove + verify, offline
let proof = engine.prove(answered, hits[0].chunk_hash, true)?;
assert!(neleus_db::verify_chunk_proof(&proof).is_ok());
```

To sign commits and checkpoints, generate a key
(`neleus_db::signing::generate_keypair_file`) and pass an `Ed25519Signer`.

## Python (HTTP)

When the database lives behind a `neleus-db serve` instance. Stdlib-only.

```python
import neleus  # sdk/python/neleus.py

c = neleus.connect("neleus://nlk_…@127.0.0.1:7117")
c.put_document("main", "nda.txt", open("nda.txt").read(), metadata={"doc_type": "policy"})

res = c.search("main", query="indemnification terms", mode="hybrid", audit=True)
proof = c.prove(res["commit"], res["hits"][0]["chunk"])
assert c.verify(proof)["valid"]
```

Run capture wraps a model call so its prompt, retrieved chunks, and output
become a committed, provable record. Note the **ordering**: retrieve and
attach chunks *before* the model call — they are inputs, not outputs.

```python
hits = c.search("main", query=question, top_k=3)
with neleus.run(url="neleus://nlk_…@127.0.0.1:7117",
                provider="anthropic", model="claude-sonnet-4-6",
                agent_id="reviewer-v1") as run:
    run.prompt(question)
    run.retrieved_chunks([h["chunk"] for h in hits["hits"]])   # before the call
    try:
        reply = anthropic_client.messages.create(...)
        run.output(reply.content[0].text)
    except Exception:
        run.abort()        # incomplete runs are not committed
        raise
# auto-commits on a clean exit; run.commit_hash is available after
```

## TypeScript

`@neleus/client` — fetch-based, Node 18+ or browser. A complete turn:

```ts
import { connect } from "@neleus/client";
import Anthropic from "@anthropic-ai/sdk";

const db = connect("neleus://nlk_…@127.0.0.1:7117");
const llm = new Anthropic();

async function agentTurn(question: string) {
  // Retrieve, then build context from full chunk text.
  const res = await db.search("main", { query: question, mode: "hybrid", topK: 3, audit: true });
  const context = (await Promise.all(res.hits.map((h) => db.chunkText(h.chunk)))).join("\n\n");

  // Model call with the retrieved context.
  const reply = await llm.messages.create({
    model: "claude-sonnet-4-6", max_tokens: 512,
    messages: [{ role: "user", content: `Context:\n${context}\n\nQuestion: ${question}` }],
  });
  const answer = reply.content[0].type === "text" ? reply.content[0].text : "";

  // Commit the audit record, anchor it, prove the top hit.
  await db.commit("main", `answer: ${question.slice(0, 40)}`, [res.audit_manifest!]);
  await db.checkpoint("main");
  const proof = await db.prove(res.commit, res.hits[0].chunk);
  console.assert((await db.verify(proof)).valid);

  return { answer, commit: res.commit };
}
```

Or use the run-capture helper:

```ts
import { withRun } from "@neleus/client";  // db from connect() above
const hits = await db.search("main", { query: question, topK: 3 });
await withRun(db, { provider: "anthropic", model: "claude-sonnet-4-6", agentId: "reviewer" },
  async (run) => {
    run.prompt(question);
    run.retrievedChunks(hits.hits.map((h) => h.chunk));
    const reply = await llm.messages.create(/* … */);
    await run.output(reply.content[0].text);
  });
```

## Rust (HTTP client)

For a Rust process talking to a remote `serve`. See
[sdk/rust](sdk/rust); the shape matches the embedded API but over HTTP.

```rust
use neleus_client::{Client, SearchOpts};
let c = Client::connect("neleus://nlk_…@127.0.0.1:7117")?;
let res = c.search("main", SearchOpts { query: Some("policy".into()), audit: true, ..Default::default() })?;
let text = String::from_utf8(c.blob_get(&res.hits[0].chunk)?)?;     // full chunk text
let proof = c.prove(&res.commit, &res.hits[0].chunk, true)?;
assert!(c.verify(&proof)?.valid);
```

## Framework integration (LangChain / LangGraph)

neleus drops in as a retrieval + memory layer. The pattern: query neleus for
context, track the retrieved hashes on the active run, commit when the turn
finishes. Sketch (adapt to your framework's exact memory interface):

```python
import neleus_native as n

class NeleusMemory:
    """Retrieval + tamper-evident audit, backed by an in-process neleus engine."""
    def __init__(self, db_path: str, agent_id: str):
        self.db = n.Neleus(db_path)
        self.agent_id = agent_id

    def context_for(self, query: str, k: int = 5) -> str:
        hits = self.db.search("main", query, mode="hybrid", top_k=k)
        self._last_query = query
        return "\n\n".join(self.db.get_blob(h["chunk"]).decode() for h in hits)

    def record(self, _output: str) -> str:
        # Called after the model responds: commit the retrieval as audit history.
        audit = self.db.record_query("main", self._last_query, principal=self.agent_id)
        commit = self.db.commit("main", "agent turn", manifests=[audit])
        self.db.checkpoint("main")
        return commit
```

Wire `context_for` into your chain's context-loading step and `record` into
its save/finish step. The retrieval is what closes the audit loop, so call
`context_for` before the model and `record` after.

## Multi-agent traces

Real agent systems hand off, swarm, and switch models mid-task. Each run carries
optional trace lineage so the whole task is one verifiable chain, not a pile of
disconnected commits:

- `trace_id` — groups every run of one logical task under one id.
- `parent_span` — the **manifest hash** of the parent run; a cryptographic span
  edge, so the causal order across steps is itself provable.
- `delegated_from` — the agent that handed off to this run's agent.

```python
# Agent A does a step under one trace, then hands off to Agent B.
with neleus.run(url=conn, provider="anthropic", model="claude-sonnet-4-6",
                agent_id="planner", trace_id=trace) as a:
    a.prompt(task); a.output(plan)
parent = a.manifest_hash

with neleus.run(url=conn, provider="openai", model="gpt-4o",   # model switch
                agent_id="executor", trace_id=trace,
                parent_span=parent, delegated_from="planner") as b:
    b.retrieved_chunks(chunks); b.prompt(step); b.output(result)
```

This maps the hard cases onto primitives you already have:

- **Agent switch** — `delegated_from` + `parent_span` make the handoff explicit
  and verifiable.
- **Swarm** — give each agent its own head/branch, set a shared `trace_id`, and
  join with a merge commit (commits take multiple parents). Note: the server
  serializes writes with a single writer lock today — fine for moderate
  concurrency, not yet tuned for large swarms hammering one head.
- **Model switch** — `model`/`provider` are per run, so a switch is just the next
  run with different values. neleus records the *declared* model; it cannot
  attest which remote model actually ran.
- **Context switch** — context is `head@commit`: a run's `retrieved_chunks` and
  the queried commit record exactly what was in scope for that step.

## Audit and proofs

This is the differentiator, so it gets its own path. After any committed
retrieval:

```python
# One chunk's proof, verified offline:
proof = db.prove(commit, chunk_hash)
assert db.verify_proof(proof)["valid"]

# A whole period as a signed bundle for an auditor:
db.audit_export("main", "2026-q1.nelaudit")          # native binding
# or:  neleus-db audit export --head main --out 2026-q1.nelaudit --sign-key agent.key
```

The bundle is self-contained: the verifier re-derives every claim from the
carried bytes, independently, with no neleus install.

## Production and operations

- **Embedded (Rust / PyO3): no server, no network.** This is the production
  path for latency-sensitive agents. Open the engine once and reuse it.
- **HTTP: run one `neleus-db serve`** behind a TLS-terminating proxy
  (loopback by default; non-loopback needs `--allow-remote` + keys). The HTTP
  SDKs are a ~1 ms round-trip on loopback — fine for production agent loops.
- **Do not spawn the CLI per call.** The old `sdk/python` subprocess fallback
  pays process-spawn latency (~10–50 ms) on every call — acceptable for
  scripts and CI, not for a request path. For non-Rust production, use the
  HTTP server (one persistent process) or, for Python, the PyO3 binding.

| Mode | Per-op latency | Use |
|---|---|---|
| Rust library / PyO3 (embedded) | µs reads, sub-ms writes | production, latency-sensitive |
| HTTP SDK → `serve` | ~1 ms loopback (+ network) | production, non-Rust or remote |
| Python subprocess fallback | 10–50 ms spawn per call | scripts, CI, evaluation only |

- **Concurrency:** the server is many-readers / single-writer (commit at a
  time). Embedded readers run concurrently against immutable snapshots.
- **Durability:** `os` (default, crash-safe) or `full` (fsync per write) in
  `meta/config.json`. See [docs/security.md](docs/security.md).
- **Console + policy enforcement:** `serve` ships a console at `/`
  (audit log, proof inspector, policy views). Declare
  write-time policies as code and the server refuses violating writes (HTTP 403,
  `code: policy_violation`); violations append to a tamper-evident log, stream to
  the console, and can fire a webhook. See [docs/policy.md](docs/policy.md).

## Encryption scope

With encryption enabled, **all data at rest is encrypted**: blobs (chunk
text, embeddings, values, prompts, outputs), all typed objects (manifests,
state, commits, checkpoints), and the derived index segments. AES-256-GCM or
ChaCha20-Poly1305 per object, Argon2id master key.

What is *not* encrypted, and exactly what it reveals:

| Path | Contents | What an attacker with file access learns |
|---|---|---|
| `refs/**` | content hashes (commit/checkpoint pointers) | that specific hashes exist — no plaintext, no values |
| `wal/*.wal` | ref names + content hashes + op codes | the same; the WAL never carries plaintext values |
| `meta/config.json` | algorithm, KDF params, random salt | configuration only; the salt is not secret |
| `meta/auth.json` | BLAKE3 **hashes** of API tokens | nothing usable — tokens are not recoverable |

So "not encrypted" here means "contains content hashes and structural
metadata, never plaintext." For a regulated deployment, put the database
directory on a full-disk-encrypted volume to cover even the hashes and
filenames; the application-layer encryption above protects the data itself
regardless. (Filenames in the CAS are content hashes, which under the threat
model only confirm *known* plaintexts — see [docs/security.md](docs/security.md).)

## Reference

### CLI contract

Every CLI call takes `--db <path>`; pass `--json` for machine-readable output
and treat a non-zero exit as failure. The full command map is in
[docs/cli.md](docs/cli.md); the HTTP routes are in
[docs/http-api.md](docs/http-api.md).

### State key encoding

`state` and `proof` commands take `--key-encoding` because keys are arbitrary
bytes. Use `utf8` for plain string keys (the common case), `hex` or `base64`
when your keys contain binary data that isn't valid UTF-8. Pick the wrong one
and the command errors rather than silently mis-keying — but match what you
wrote with what you read.

```bash
neleus-db --db ./db state set main user:42 ./value.bin --key-encoding utf8
neleus-db --db ./db state get main 6b657931 --key-encoding hex
```
