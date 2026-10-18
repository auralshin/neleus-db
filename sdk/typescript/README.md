# @neleus/client

TypeScript HTTP client for a `neleus-db serve` instance. Node 18+ or
browsers, no runtime dependencies.

```bash
npm install @neleus/client
```

```ts
import { connect, withRun } from "@neleus/client";

const c = connect("neleus://nlk_...@127.0.0.1:7117"); // or new Client(url, { token })
await c.putDocument("main", "kb.md", "policy text", { metadata: { acl: ["group:hr"] } });
const res = await c.search("main", { query: "reset policy" });
const proof = await c.prove(res.commit, res.hits[0].chunk);
const { valid } = await c.verify(proof);
const bundle = await c.exportBundle("main"); // .nelaudit bytes

await withRun(c, { provider: "anthropic", model: "claude-sonnet-4-6" }, async (run) => {
  run.prompt(question).retrievedChunks(res.hits.map((h) => h.chunk));
  await run.output(reply);
});
```

Methods: `health`, `blobPut`, `blobGet`, `chunkText`, `putDocument`,
`commit`, `search` (`{ query, embedding, mode, topK, filter, commit }`),
`prove`, `verify`, `stateGet`, `stateSet`, `sessionAppend`, `sessionList`,
`checkpoint`, `auditQueries`, `exportBundle`, `run`. Errors throw
`NeleusError` with `.code`, `.hint`, `.status`.

Test: `npm run build && npm test` (needs `cargo build --release` at the repo
root, or `NELEUS_BIN`).

Routes: [docs/http-api.md](../../docs/http-api.md).
