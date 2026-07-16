# @neleus/client

TypeScript client for [neleus-db](../../). Talks to a `neleus-db serve`
instance over HTTP. Works in Node 18+ (global `fetch`) and browsers. No
runtime dependencies.

```bash
npm install @neleus/client
```

```ts
import { connect } from "@neleus/client";

const c = connect("neleus://nlk_…@127.0.0.1:7117");   // or new Client(url, { token })

const { commit } = await c.putDocument("main", "kb.md", "policy text", {
  metadata: { doc_type: "policy", acl: ["group:hr"] },
});

const res = await c.search("main", { query: "reset policy", mode: "hybrid", audit: true });

// prove a hit and verify it
const proof = await c.prove(res.commit, res.hits[0].chunk);
const verdict = await c.verify(proof);          // { valid: true, anchor: "doc" }

// offline-verifiable audit bundle
const bundle = await c.exportBundle("main");     // Uint8Array (.nelaudit)
```

Run capture — wrap a model call so its prompt, retrieved chunks, and output
become a content-addressed, provable record:

```ts
import { withRun } from "@neleus/client";

await withRun(c, { provider: "anthropic", model: "claude-sonnet-4-6", agentId: "reviewer" },
  async (run) => {
    run.prompt(question);
    run.retrievedChunks(res.hits.map((h) => h.chunk));
    const reply = await anthropic.messages.create(/* … */);
    await run.output(reply.content[0].text);
  });
// auto-commits: prompt, chunks, and output are now provably linked.
```

## API

`connect(connString?, opts?)` — from a `neleus://[token@]host[:port]` string or
`$NELEUS_URL`. Or `new Client(url, { token?, timeoutMs?, fetch? })`. Then:

- `health()`, `putDocument(head, source, text, opts?)`, `commit(head, message, manifests?)`
- `search(at, { query?, embedding?, mode?, topK?, filter?, audit? })`
- `prove(commit, chunk, includeContent?)`, `verify(proofCbor)`
- `stateGet/stateSet`, `sessionAppend/sessionList`, `checkpoint(head)`
- `auditQueries`, `exportBundle`
- `run(opts)` / `withRun(client, opts, fn)`

`at` accepts a head name or a 64-hex commit hash (time-travel).

Failed calls throw `NeleusError` carrying `.code` (e.g. `policy_violation`,
`unauthorized`), `.hint`, and `.status`.

## Build & test

```bash
npm run build      # tsc -> dist/
npm test           # spawns the release binary, runs e2e tests
```

Tests need the `neleus-db` release binary (`cargo build --release` at the repo
root) or `NELEUS_BIN` pointing at it; without it the suite skips cleanly.

For the embedded, in-process path (no server), use the
[native Python binding](../python-native) or the Rust crate directly.
