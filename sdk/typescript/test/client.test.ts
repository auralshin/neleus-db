// End-to-end tests. Spawns a real `neleus-db serve` against a temp DB and
// drives the built client against it. Build the binary first:
//   (cd ../.. && cargo build --release)
// then:
//   npm run build && node --test
//
// If the binary is missing the suite skips with a clear message rather than
// failing — so `npm test` stays green on a checkout without a Rust build.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "../dist/index.js";

const BIN = process.env.NELEUS_BIN ?? join(import.meta.dirname, "../../../target/release/neleus-db");
const available = existsSync(BIN);

let server: ChildProcess | undefined;
let url = "";
let token = "";
let dbDir = "";

before(async () => {
  if (!available) return;
  dbDir = mkdtempSync(join(tmpdir(), "neleus-ts-"));
  const db = join(dbDir, "db");
  run(["--db", db, "db", "init", db]);
  const out = run(["--db", db, "--json", "auth", "add-key", "--id", "ts", "--role", "admin"]);
  token = JSON.parse(out).token;

  const port = 7300 + Math.floor(Math.random() * 400);
  url = `http://127.0.0.1:${port}`;
  server = spawn(BIN, ["--db", db, "serve", "--addr", `127.0.0.1:${port}`], { stdio: "ignore" });
  await waitFor(async () => {
    try {
      await new Client(url, { token }).health();
      return true;
    } catch {
      return false;
    }
  });
});

after(() => {
  server?.kill();
  if (dbDir) rmSync(dbDir, { recursive: true, force: true });
});

function run(args: string[]): string {
  const r = spawnSync(BIN, args, { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`neleus-db ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
}

async function waitFor(pred: () => Promise<boolean>, ms = 5000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await pred()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("server did not become ready");
}

const maybe = (name: string, fn: () => Promise<void>) =>
  test(name, { skip: available ? false : "release binary not built (see file header)" }, fn);

maybe("ingest, search, prove, verify", async () => {
  const c = new Client(url, { token });
  const doc = await c.putDocument("main", "kb.md", "TypeScript agents need verifiable audit trails.");
  assert.ok(doc.commit);

  const res = await c.search("main", { query: "verifiable audit", mode: "semantic", audit: true });
  assert.ok(res.hits.length > 0);
  assert.ok(res.audit_manifest);

  const proof = await c.prove(res.commit, res.hits[0].chunk);
  const verdict = await c.verify(proof);
  assert.equal(verdict.valid, true);
  assert.equal(verdict.anchor, "doc");
});

maybe("compliance status and export bundle", async () => {
  const c = new Client(url, { token });
  await c.putDocument("comp", "kb", "auditable corpus");
  const res = await c.search("comp", { query: "auditable", mode: "semantic", audit: true });
  await c.commit("comp", "audit", [res.audit_manifest!]);
  await c.checkpoint("comp");

  const frameworks = await c.frameworks();
  assert.ok(frameworks.length >= 12);

  const status = await c.complianceStatus("comp");
  const eu = status.find((s) => s.id === "eu-ai-act")!;
  assert.equal(eu.overall, "pass");

  const bundle = await c.exportBundle("comp");
  assert.ok(bundle.byteLength > 0);
  // bundle starts with the NELAUDIT magic
  assert.equal(new TextDecoder().decode(bundle.slice(0, 8)), "NELAUDIT");
});

maybe("run capture records a manifest", async () => {
  const c = new Client(url, { token });
  const run = c.run({ head: "main", provider: "anthropic", model: "claude-sonnet-4-6", agentId: "rev" });
  run.prompt("question");
  await run.output("answer");
  const out = await run.commit();
  assert.ok(out.manifest);
});

maybe("session round-trip", async () => {
  const c = new Client(url, { token });
  await c.sessionAppend("main", "s1", "hello", { role: "user", ttlSecs: 3600 });
  const turns = await c.sessionList("main", "s1");
  assert.equal(turns.length, 1);
  assert.equal(turns[0].content, "hello");
});

maybe("bad token is rejected", async () => {
  const c = new Client(url, { token: "nlk_wrong" });
  await assert.rejects(() => c.health(), /invalid bearer token/);
});
