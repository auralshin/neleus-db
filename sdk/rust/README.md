# neleus-client

Rust HTTP client for [neleus-db](../../). Talks to a `neleus-db serve`
instance. Hand-rolled std-only HTTP — no tokio, no reqwest.

```toml
[dependencies]
neleus-client = { path = "../neleus-db/sdk/rust" }
```

```rust
use neleus_client::{Client, DocOpts, SearchOpts};

let c = Client::connect("neleus://nlk_…@127.0.0.1:7117")?;   // or Client::new(url, token)

let doc = c.put_document("main", "kb.md", "policy text", DocOpts::default())?;

let res = c.search("main", SearchOpts {
    query: Some("reset policy".into()),
    mode: Some("hybrid".into()),
    audit: true,
    ..Default::default()
})?;

let proof = c.prove(&res.commit, &res.hits[0].chunk, true)?;
assert!(c.verify(&proof)?.valid);

// offline-verifiable audit bundle
let bundle = c.export_bundle("main", None, None)?;
std::fs::write("q1.nelaudit", bundle)?;
```

Run capture:

```rust
c.run("anthropic", "claude-sonnet-4-6")
    .head("main")
    .agent_id("reviewer")
    .prompt(&question)
    .output(reply.as_bytes())?
    .commit()?;
```

## TLS

`http://` only. The server has no in-process TLS by design — terminate TLS
with a reverse proxy or SSH tunnel and point the client at that endpoint.

## Embedded vs client

This crate is a **client**. For the embedded, in-process engine (no server,
no network), depend on the `neleus-db` crate and use `neleus_db::Engine`
directly — that's the fastest path and what the server itself runs on.

## Test

```bash
cargo test         # spins up an in-process server and drives the client
```
