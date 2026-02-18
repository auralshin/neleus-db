# Integration Guide

This guide covers how to integrate `neleus-db` from Rust, TypeScript/JavaScript, Go, and Python.

## Integration modes

`neleus-db` supports two integration modes:

- Embedded Rust library API (best performance, direct typed access)
- CLI process interface (best for non-Rust stacks)

## 1) Rust integration (library mode)

### Add dependency

```toml
[dependencies]
neleus-db = { path = "../neleus-db" }
anyhow = "1"
```

### Minimal workflow

```rust
use anyhow::Result;
use neleus_db::{Database, manifest::{RunManifest, ToolCallRef, now_unix}};

fn main() -> Result<()> {
    Database::init("./neleus_db")?;
    let db = Database::open("./neleus_db")?;

    let head = "main";
    let base_root = db
        .refs
        .state_get(head)?
        .unwrap_or(db.state_store.empty_root()?);

    let new_root = db.state_store.set(base_root, b"agent/session/1/status", b"done")?;
    db.refs.state_set(head, new_root)?;

    let prompt = db.blob_store.put(b"summarize this file")?;
    let ts = now_unix();
    let run_manifest = RunManifest {
        schema_version: 1,
        model: "gpt-4.1".into(),
        prompt,
        tool_calls: Vec::<ToolCallRef>::new(),
        inputs: vec![],
        outputs: vec![],
        started_at: ts,
        ended_at: ts,
    };
    let manifest_hash = db.manifest_store.put_manifest(&run_manifest)?;

    let parents = db.refs.head_get(head)?.map(|h| vec![h]).unwrap_or_default();
    let commit_hash = db.commit_store.create_commit(
        parents,
        new_root,
        vec![manifest_hash],
        "agent1".into(),
        "run complete".into(),
    )?;
    db.refs.head_set(head, commit_hash)?;

    Ok(())
}
```

## 2) Cross-language integration (CLI mode)

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

### Common command sequence

```bash
neleus-db --db ./neleus_db --json db init ./neleus_db
neleus-db --db ./neleus_db --json state set main my-key ./value.bin --key-encoding utf8
neleus-db --db ./neleus_db --json state get main my-key --key-encoding utf8
neleus-db --db ./neleus_db --json commit new --head main --author agent1 --message "snapshot"
```

## TypeScript / JavaScript example

```ts
import { execFileSync } from "node:child_process";

function run(args: string[]) {
  const out = execFileSync(
    "neleus-db",
    ["--db", "./neleus_db", "--json", ...args],
    {
      encoding: "utf8",
    },
  );
  return JSON.parse(out);
}

const blob = run(["blob", "put", "./input.txt"]);
console.log(blob.hash);
```

## Python example

```python
import json
import subprocess

def run(args):
    out = subprocess.check_output(
        ["neleus-db", "--db", "./neleus_db", "--json"] + args,
        text=True,
    )
    return json.loads(out)

res = run(["log", "main"])
print(res)
```

## Go example

```go
package main

import (
 "encoding/json"
 "fmt"
 "os/exec"
)

func run(args ...string) (map[string]any, error) {
 base := []string{"--db", "./neleus_db", "--json"}
 cmd := exec.Command("neleus-db", append(base, args...)...)
 out, err := cmd.Output()
 if err != nil {
  return nil, err
 }
 var v map[string]any
 if err := json.Unmarshal(out, &v); err != nil {
  return nil, err
 }
 return v, nil
}

func main() {
 v, err := run("log", "main")
 if err != nil {
  panic(err)
 }
 fmt.Println(v)
}
```

## Operational guidance

- Canonical source of truth is blobs/objects + commits; derived indexes can be rebuilt.
- Use commit hashes as durable checkpoints in your application metadata.
- For high-throughput non-Rust usage, wrap CLI or library in a local sidecar (HTTP/gRPC) to avoid process startup overhead per request.
- Enable verify-on-read in environments where stronger integrity guarantees are required.

## Suggested integration pattern for agent systems

1. Store large input/output artifacts in `blob_store`.
2. Keep lightweight pointers/flags in `state_store`.
3. Emit `RunManifest` and `DocManifest` for traceability.
4. Commit every meaningful step (`commit_store.create_commit` + `refs.head_set`).
5. Build/rebuild search indexes from commit heads (`index build`).
