# neleus-client

Rust HTTP client for a `neleus-db serve` instance. std-only, `http://` only;
terminate TLS in a proxy. For in-process use, depend on `neleus-db` and use
`neleus_db::Engine`.

```toml
[dependencies]
neleus-client = { path = "../neleus-db/sdk/rust" }
```

```rust
use neleus_client::{Client, DocOpts, SearchOpts};

let c = Client::connect("neleus://nlk_...@127.0.0.1:7117")?; // or Client::new(url, token)
c.put_document("main", "kb.md", "policy text", DocOpts::default())?;
let res = c.search("main", SearchOpts { query: Some("reset policy".into()), ..Default::default() })?;
let proof = c.prove(&res.commit, &res.hits[0].chunk, true, None)?;
assert!(c.verify(&proof)?.valid);
std::fs::write("q1.nelaudit", c.export_bundle("main", None, None)?)?;

c.run("anthropic", "claude-sonnet-4-6").head("main").prompt(&question)
    .output(reply.as_bytes())?.commit()?;
```

Methods: `health`, `blob_put`, `blob_get`, `put_document`, `commit`, `search`,
`prove`, `verify`, `session_append`, `session_list`, `checkpoint`,
`export_bundle`, `run` (builder: `head`, `agent_id`, `prompt`,
`system_prompt`, `retrieved_chunks`, `input`, `output`, `message`, `commit`).

Test: `cargo test` (starts an in-process server).

Routes: [docs/http-api.md](../../docs/http-api.md).
