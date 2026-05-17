# Integration Guide

This guide covers how to integrate `neleus-db` from Rust, Python, TypeScript/JavaScript, and Go.

## Integration modes

`neleus-db` supports two integration modes:

- **Embedded Rust library API** — best performance, direct typed access, no subprocess overhead
- **CLI process interface** — best for non-Rust stacks; parse `--json` output

---

## 1) Rust integration (library mode)

### Add dependency

```toml
[dependencies]
neleus-db = { path = "../neleus-db" }
anyhow = "1"
```

### Minimal agent run workflow

```rust
use anyhow::Result;
use neleus_db::{Database, manifest::{RunManifest, MANIFEST_SCHEMA_VERSION}};

fn main() -> Result<()> {
    Database::init("./neleus_db")?;
    let db = Database::open("./neleus_db")?;

    let head = "main";

    // Store the prompt blob.
    let prompt = db.blob_store.put(b"Summarise this codebase.")?;

    // Optionally store the system prompt and model parameters as separate blobs.
    let system_prompt_hash = db.blob_store.put(b"You are a code analyst.")?;
    let params_json = serde_json::to_vec(&serde_json::json!({"max_tokens": 1024, "temperature": 0.0}))?;
    let model_parameters_hash = db.blob_store.put(&params_json)?;

    // ... make the model call ...
    let output = db.blob_store.put(b"The codebase implements a Merkle-DAG store.")?;

    let now = neleus_db::clock::now_unix()?;
    let run = RunManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        model: "claude-sonnet-4-6".into(),
        prompt,
        tool_calls: vec![],
        inputs: vec![],
        outputs: vec![output],
        started_at: now,
        ended_at: now,
        provider: Some("anthropic".into()),
        system_prompt: Some(system_prompt_hash),
        model_parameters: Some(model_parameters_hash),
        retrieved_chunks: vec![],          // populate from RAG search results
        sdk_version: Some("neleus-rs/0.1".into()),
        agent_id: Some("code-analyst-v1".into()),
    };
    let manifest_hash = db.manifest_store.put_manifest(&run)?;

    let commit_hash = db.create_commit_at_head(head, "agent1", "analysis run", vec![manifest_hash])?;

    println!("commit: {commit_hash}");
    Ok(())
}
```

> **On replayability:** neleus-db captures all inputs, retrieved context, and provider metadata
> needed to reconstruct a run. Because hosted LLMs are non-deterministic and may change over
> time, runs are *auditable and state-replayable* rather than bit-for-bit reproducible.

---

## 2) Python SDK (recommended for Python stacks)

Copy [`sdk/python/neleus.py`](sdk/python/neleus.py) next to your project. Requires the
`neleus-db` binary on `PATH`.

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
    run.retrieved_chunks(chunk_hashes)   # closes the RAG audit loop

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": user_question}],
    )
    run.output(response.content[0].text)
# auto-commits here — manifest hash available at run.manifest_hash
```

See [`examples/06_claude_run.py`](examples/06_claude_run.py) for a complete working example
including document ingestion, semantic search, and state proofs.

### Auto-commit vs explicit commit

```python
# Auto-commit on __exit__ (default):
with neleus.run(...) as run:
    ...

# Explicit commit with a custom message:
with neleus.run(...) as run:
    ...
    manifest_hash = run.commit(message="policy Q&A — run 42")

# Abort (no commit):
with neleus.run(...) as run:
    run.abort()
```

---

## 3) Cross-language CLI integration

Use the `neleus-db` binary as a local subprocess and parse `--json` output.

### Contract

- Always pass `--db <path>` explicitly.
- Use `--json` for machine-readable output.
- Treat non-zero exit codes as failures.
- Keep one writer coordinator per DB path.

### Key/value encoding

For `state` and `proof` commands, select key encoding explicitly:

- `--key-encoding utf8`
- `--key-encoding hex`
- `--key-encoding base64`

### Capturing a model run from the CLI

```bash
# 1. Store the prompt blob
PROMPT_HASH=$(neleus-db --db ./neleus_db --json blob put ./prompt.txt | jq -r .hash)

# 2. Store the system prompt
SP_HASH=$(neleus-db --db ./neleus_db --json blob put ./system.txt | jq -r .hash)

# 3. (After the model call) store the output
OUT_HASH=$(neleus-db --db ./neleus_db --json blob put ./output.txt | jq -r .hash)

# 4. Create a run manifest with full metadata
MANIFEST=$(neleus-db --db ./neleus_db --json manifest put-run \
  --model claude-sonnet-4-6 \
  --provider anthropic \
  --prompt-file ./prompt.txt \
  --system-prompt-file ./system.txt \
  --io-hashes "out:$OUT_HASH" \
  --param max_tokens=1024 \
  --param temperature=0 \
  --agent-id policy-reviewer-v1 \
  --retrieved-chunk "$CHUNK_HASH_1" \
  --retrieved-chunk "$CHUNK_HASH_2" | jq -r .manifest_hash)

# 5. Commit
neleus-db --db ./neleus_db --json commit new \
  --head main --author agent1 --message "policy run" \
  --manifest "$MANIFEST"
```

### TypeScript / JavaScript

```ts
import { execFileSync } from "node:child_process";

function nb(args: string[]) {
  const out = execFileSync(
    "neleus-db",
    ["--db", "./neleus_db", "--json", ...args],
    { encoding: "utf8" },
  );
  return JSON.parse(out);
}

const blob = nb(["blob", "put", "./input.txt"]);
console.log(blob.hash);
```

### Go

```go
package main

import (
    "encoding/json"
    "fmt"
    "os/exec"
)

func nb(args ...string) (map[string]any, error) {
    base := []string{"--db", "./neleus_db", "--json"}
    cmd := exec.Command("neleus-db", append(base, args...)...)
    out, err := cmd.Output()
    if err != nil { return nil, err }
    var v map[string]any
    return v, json.Unmarshal(out, &v)
}

func main() {
    v, err := nb("log", "main")
    if err != nil { panic(err) }
    fmt.Println(v)
}
```

---

## Encryption scope

When encryption is enabled, **blobs and objects** (including run manifests, state segments, and
commits) are encrypted at rest with the configured AEAD algorithm. The following are **not
encrypted** by default and may leak information in regulated environments:

| Path | Encrypted? |
|------|-----------|
| `blobs/**` | Yes |
| `objects/**` | Yes |
| `index/<commit>/search_index.cbor` | Yes (since v3, issue #10) |
| `refs/heads/*`, `refs/states/*` | No — contain only hashes |
| `wal/*.wal` | No — contain only hashes and op codes |
| `meta/config.json` | No — contains algorithm config, not data |
| Key paths (`memory/last-summary`) | No — stored as filenames in refs |

For highly sensitive workloads, keep the DB on an encrypted volume and restrict filesystem access.

---

## Operational guidance

- Canonical truth lives in `blobs/` + `objects/` + commits; derived indexes can always be rebuilt.
- Use commit hashes as durable checkpoints in application metadata.
- For high-throughput non-Rust usage, wrap the library or CLI in a local sidecar to amortise
  process-startup overhead across requests.
- Enable `verify_on_read` in environments where stronger integrity guarantees are required.

## Suggested integration pattern for agent systems

```text
1. Ingest documents → DocManifest (chunks + embeddings)
2. Query → search semantic/vector → top-k chunk hashes
3. Model call → RunManifest (prompt, system_prompt, model_parameters, retrieved_chunks, outputs)
4. Claim → ProvenanceRecord (claim_text, evidence → chunk hashes, confidence, run_manifest)
5. Commit → links RunManifest + ProvenanceManifest into the Merkle DAG
6. Proof → prove chunk was retrieved; prove claim links to this run; export audit bundle
```
