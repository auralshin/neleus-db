// neleus-db TypeScript SDK — a typed client for `neleus-db serve`.
// Works in Node 18+ (global fetch) and browsers. No runtime dependencies.

export type SearchMode = "semantic" | "vector" | "hybrid";
export type ComplianceStatus = "pass" | "warn" | "fail";

export interface Filter {
  tenant?: string;
  doc_type?: string;
  language?: string;
  acl?: string[];
  at?: number;
}

export interface Hit {
  chunk: string;
  score: number;
  preview: string;
}

export interface SearchResult {
  commit: string;
  hits: Hit[];
  audit_manifest: string | null;
}

export interface Framework {
  id: string;
  name: string;
  jurisdiction: string;
  region: string;
  citation: string;
}

export interface FrameworkStatus extends Framework {
  overall: ComplianceStatus;
  required_fails: number;
}

export interface CheckResult {
  id: string;
  label: string;
  status: ComplianceStatus;
  severity: "required" | "recommended";
  detail: string;
}

export interface ComplianceReport {
  framework: string;
  name: string;
  jurisdiction: string;
  region: string;
  citation: string;
  head: string;
  retrievals: number;
  overall: ComplianceStatus;
  checks: CheckResult[];
  mappings: { requirement: string; mechanism: string }[];
}

export interface AuditRecord {
  commit: string;
  manifest: string;
  queried_commit: string;
  executed_at: number;
  principal: string | null;
  mode: string;
  top_k: number;
  filters: string | null;
  hits: { chunk: string; score_micro: number }[];
}

export interface SessionTurn {
  seq: number;
  role: string | null;
  created_at: number;
  expires_at: number | null;
  content: string;
}

export class NeleusError extends Error {
  /** Stable neleus error code, e.g. `"policy_violation"`. Branch on this. */
  code?: string;
  /** Server-supplied hint on how to fix it. */
  hint?: string;
  /** HTTP status. */
  status?: number;
  constructor(message: string, info: { code?: string; hint?: string; status?: number } = {}) {
    super(message);
    this.name = "NeleusError";
    this.code = info.code;
    this.hint = info.hint;
    this.status = info.status;
  }
}

export interface ClientOptions {
  /** Bearer token (the `nlk_…` value from `auth add-key`). */
  token?: string;
  /** Per-request timeout in ms (default 600_000). */
  timeoutMs?: number;
  /** Override fetch (e.g. node-fetch on older Node). Defaults to global fetch. */
  fetch?: typeof fetch;
}

export class Client {
  private url: string;
  private token?: string;
  private timeoutMs: number;
  private fetchImpl: typeof fetch;

  constructor(url: string, opts: ClientOptions = {}) {
    this.url = url.replace(/\/$/, "");
    this.token = opts.token;
    this.timeoutMs = opts.timeoutMs ?? 600_000;
    const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (!f) throw new NeleusError("no fetch available; pass opts.fetch (Node < 18)");
    this.fetchImpl = f;
  }

  private async req(method: string, path: string, body?: unknown, raw?: BodyInit): Promise<Response> {
    const headers: Record<string, string> = {};
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    let payload: BodyInit | undefined = raw;
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    } else if (raw !== undefined) {
      headers["content-type"] = "application/octet-stream";
    }
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(this.url + path, {
        method,
        headers,
        body: payload,
        signal: ctrl.signal,
      });
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        let code: string | undefined;
        let hint: string | undefined;
        try {
          const b = (await res.json()) as { error?: string; code?: string; hint?: string };
          msg = b.error || msg;
          code = b.code;
          hint = b.hint;
        } catch {
          /* non-json */
        }
        throw new NeleusError(hint ? `${msg} — fix: ${hint}` : msg, { code, hint, status: res.status });
      }
      return res;
    } finally {
      clearTimeout(t);
    }
  }

  private async json<T>(method: string, path: string, body?: unknown): Promise<T> {
    return (await (await this.req(method, path, body)).json()) as T;
  }

  // ---- core ----

  health(): Promise<{ ok: boolean; version: string }> {
    return this.json("GET", "/v1/health");
  }

  async blobGet(hash: string): Promise<Uint8Array> {
    const res = await this.req("GET", `/v1/blobs/${hash}`);
    return new Uint8Array(await res.arrayBuffer());
  }

  /** Convenience: full UTF-8 text of a blob (e.g. a retrieved chunk). */
  async chunkText(hash: string): Promise<string> {
    return new TextDecoder().decode(await this.blobGet(hash));
  }

  async blobPut(bytes: Uint8Array | string): Promise<string> {
    const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    const res = await this.req("POST", "/v1/blobs", undefined, data as BodyInit);
    return ((await res.json()) as { hash: string }).hash;
  }

  putDocument(
    head: string,
    source: string,
    text: string,
    opts: { chunkSize?: number; overlap?: number; metadata?: Filter & Record<string, unknown> } = {},
  ): Promise<{ manifest: string; commit: string }> {
    return this.json("POST", "/v1/documents", {
      head,
      source,
      text,
      chunk_size: opts.chunkSize ?? 512,
      overlap: opts.overlap ?? 64,
      metadata: opts.metadata ?? null,
    });
  }

  commit(head: string, message: string, manifests: string[] = []): Promise<{ commit: string }> {
    return this.json("POST", "/v1/commits", { head, message, manifests });
  }

  search(
    at: string,
    opts: { query?: string; embedding?: number[]; mode?: SearchMode; topK?: number; filter?: Filter; audit?: boolean } = {},
  ): Promise<SearchResult> {
    return this.json("POST", "/v1/search", {
      at,
      mode: opts.mode ?? "hybrid",
      query: opts.query ?? null,
      embedding: opts.embedding ?? null,
      top_k: opts.topK ?? 10,
      filter: opts.filter ?? null,
      audit: opts.audit ?? false,
    });
  }

  async prove(commit: string, chunk: string, includeContent = true): Promise<string> {
    const r = await this.json<{ proof_cbor: string }>("POST", "/v1/proofs/chunk", {
      commit,
      chunk,
      include_content: includeContent,
    });
    return r.proof_cbor;
  }

  verify(proofCbor: string): Promise<{ valid: boolean; anchor?: string; error?: string }> {
    return this.json("POST", "/v1/proofs/verify", { proof_cbor: proofCbor });
  }

  // ---- state ----

  async stateGet(head: string, key: Uint8Array): Promise<Uint8Array | null> {
    const r = await this.json<{ value: string | null }>("POST", "/v1/state/get", {
      head,
      key: b64(key),
    });
    return r.value ? unb64(r.value) : null;
  }

  stateSet(head: string, key: Uint8Array, value: Uint8Array): Promise<{ root: string }> {
    return this.json("POST", "/v1/state/set", { head, key: b64(key), value: b64(value) });
  }

  // ---- sessions ----

  sessionAppend(
    head: string,
    sessionId: string,
    content: string,
    opts: { role?: string; ttlSecs?: number } = {},
  ): Promise<{ seq: number; content_hash: string }> {
    return this.json("POST", "/v1/sessions/append", {
      head,
      session_id: sessionId,
      content,
      role: opts.role ?? null,
      ttl_secs: opts.ttlSecs ?? null,
    });
  }

  async sessionList(head: string, sessionId: string): Promise<SessionTurn[]> {
    const r = await this.json<{ turns: SessionTurn[] }>("POST", "/v1/sessions/list", {
      head,
      session_id: sessionId,
    });
    return r.turns;
  }

  // ---- checkpoints ----

  async checkpoint(head: string): Promise<string> {
    const r = await this.json<{ checkpoint: string }>("POST", "/v1/checkpoints", { head });
    return r.checkpoint;
  }

  // ---- compliance ----

  async frameworks(): Promise<Framework[]> {
    return (await this.json<{ frameworks: Framework[] }>("GET", "/v1/compliance/frameworks")).frameworks;
  }

  async complianceStatus(head: string, from?: number, to?: number): Promise<FrameworkStatus[]> {
    return (
      await this.json<{ frameworks: FrameworkStatus[] }>("POST", "/v1/compliance/status", { head, ...range(from, to) })
    ).frameworks;
  }

  complianceCheck(head: string, framework: string, from?: number, to?: number): Promise<ComplianceReport> {
    return this.json("POST", "/v1/compliance/check", { head, framework, ...range(from, to) });
  }

  // ---- audit ----

  async auditQueries(head: string, from?: number, to?: number): Promise<AuditRecord[]> {
    return (await this.json<{ records: AuditRecord[] }>("POST", "/v1/audit/queries", { head, ...range(from, to) })).records;
  }

  async auditReport(head: string, framework: string, from?: number, to?: number): Promise<string> {
    return (await this.json<{ markdown: string }>("POST", "/v1/audit/report", { head, framework, ...range(from, to) })).markdown;
  }

  /** Download a self-contained `.nelaudit` bundle (tamper-evident, offline-verifiable). */
  async exportBundle(head: string, from?: number, to?: number): Promise<Uint8Array> {
    const res = await this.req("POST", "/v1/audit/export", { head, ...range(from, to) });
    return new Uint8Array(await res.arrayBuffer());
  }

  // ---- run capture ----

  /** Begin recording one model invocation. Call `.commit()` (or use `withRun`) to persist. */
  run(opts: RunOptions): Run {
    return new Run(this, opts);
  }
}

export interface RunOptions {
  head?: string;
  provider: string;
  model: string;
  agentId?: string;
  modelParameters?: Record<string, unknown>;
  sdkVersion?: string;
  author?: string;
  message?: string;
}

export class Run {
  private inputs: string[] = [];
  private outputs: string[] = [];
  private retrieved: string[] = [];
  private systemPrompt?: string;
  private promptText?: string;
  private startedAt = Math.floor(Date.now() / 1000);

  constructor(private client: Client, private opts: RunOptions) {}

  systemPromptText(text: string): this {
    this.systemPrompt = text;
    return this;
  }
  prompt(text: string): this {
    this.promptText = text;
    return this;
  }
  retrievedChunks(hashes: string[]): this {
    this.retrieved.push(...hashes);
    return this;
  }
  async input(content: string): Promise<this> {
    this.inputs.push(await this.client.blobPut(content));
    return this;
  }
  async output(content: string): Promise<this> {
    this.outputs.push(await this.client.blobPut(content));
    return this;
  }

  /** Persist the RunManifest and commit it. Returns `{ manifest, commit }`. */
  async commit(): Promise<{ manifest: string; commit: string | null }> {
    return this.client["json"]("POST", "/v1/runs", {
      head: this.opts.head ?? "main",
      model: this.opts.model,
      provider: this.opts.provider,
      prompt: this.promptText ?? "",
      system_prompt: this.systemPrompt ?? null,
      model_parameters: this.opts.modelParameters ?? null,
      inputs: this.inputs,
      outputs: this.outputs,
      retrieved_chunks: this.retrieved,
      agent_id: this.opts.agentId ?? null,
      sdk_version: this.opts.sdkVersion ?? null,
      started_at: this.startedAt,
      ended_at: Math.floor(Date.now() / 1000),
      message: this.opts.message ?? `${this.opts.provider}/${this.opts.model} run`,
      author: this.opts.author ?? "agent",
      commit: true,
    });
  }
}

/** Run `fn` with a `Run`, then auto-commit unless `fn` threw. */
export async function withRun(
  client: Client,
  opts: RunOptions,
  fn: (run: Run) => Promise<void>,
): Promise<{ manifest: string; commit: string | null }> {
  const run = client.run(opts);
  await fn(run);
  return run.commit();
}

function range(from?: number, to?: number): Record<string, number> {
  const out: Record<string, number> = {};
  if (from !== undefined) out.from = from;
  if (to !== undefined) out.to = to;
  return out;
}

// btoa/atob are global in Node 18+ and browsers (typed via the DOM lib).
function b64(bytes: Uint8Array): string {
  let s = "";
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const DEFAULT_PORT = 7117;

/** Parse `neleus://[token@]host[:port]` (or `neleuss://` for TLS) into `{ url, token }`. */
export function parseConnString(conn: string): { url: string; token?: string } {
  let proto: string;
  let rest: string;
  if (conn.startsWith("neleuss://")) {
    proto = "https";
    rest = conn.slice("neleuss://".length);
  } else if (conn.startsWith("neleus://")) {
    proto = "http";
    rest = conn.slice("neleus://".length);
  } else {
    throw new NeleusError(`not a neleus connection string: ${conn}`, { code: "bad_request" });
  }
  rest = rest.replace(/\/$/, "");
  let token: string | undefined;
  const at = rest.indexOf("@");
  if (at >= 0) {
    token = rest.slice(0, at) || undefined;
    rest = rest.slice(at + 1);
  }
  if (!rest.includes(":")) rest = `${rest}:${DEFAULT_PORT}`;
  return { url: `${proto}://${rest}`, token };
}

// connStr: a neleus:// string, an http(s):// base URL, or undefined -> $NELEUS_URL.
export function connect(connStr?: string, opts: ClientOptions = {}): Client {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
    ?.env?.NELEUS_URL;
  const conn = connStr ?? env;
  if (conn && (conn.startsWith("neleus://") || conn.startsWith("neleuss://"))) {
    const { url, token } = parseConnString(conn);
    return new Client(url, { ...opts, token: opts.token ?? token });
  }
  return new Client(conn ?? `http://127.0.0.1:${DEFAULT_PORT}`, opts);
}
