// Typed client for a `neleus-db serve` instance. The token is kept in
// localStorage on this machine only and sent solely to the server URL you
// enter — nowhere else.
//
// When the console is served same-origin by the Rust server on loopback, the
// server injects `window.__NELEUS_BOOTSTRAP__` with the bearer token. In that
// case the client targets `window.location.origin` and auto-connects on load.

declare global {
  interface Window {
    __NELEUS_BOOTSTRAP__?: string;
  }
}

export type Status = "pass" | "warn" | "fail";

export interface ChainSummary {
  intact: boolean | null;
  length: number;
  signed: number;
  latest?: string;
  error?: string;
}

export interface HeadSummary {
  name: string;
  commit: string;
  chain: ChainSummary;
  retrievals_30d: number;
  principals_30d: string[];
  last_retrieval_at: number | null;
}

export interface ComplianceSummary {
  generated_at: number;
  heads: HeadSummary[];
  encryption_enabled: boolean;
  retention_min_secs: number | null;
}

export interface Framework {
  id: string;
  name: string;
  jurisdiction: string;
  region: string;
  citation: string;
}

export interface FrameworkStatus extends Framework {
  overall: Status;
  required_fails: number;
}

export interface CheckResult {
  id: string;
  label: string;
  status: Status;
  severity: "required" | "recommended";
  detail: string;
}

export interface ComplianceReport {
  framework: string;
  jurisdiction: string;
  region: string;
  name: string;
  citation: string;
  head: string;
  retrievals: number;
  overall: Status;
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

// ---- policy-enforcement layer ----

export type RuleKind =
  | "require-tamper-evident-chain"
  | "require-signed-checkpoints"
  | "require-encryption-at-rest"
  | "retention-floor"
  | "require-principal"
  | "require-signed-commits"
  | "require-provenance";

export type Rule =
  | { kind: Exclude<RuleKind, "retention-floor"> }
  | { kind: "retention-floor"; min_secs: number };

export type Mode = "monitor" | "enforce";
export type Severity = "required" | "recommended";

export interface Policy {
  id: string;
  description?: string;
  heads?: string[];
  rule: Rule;
  mode: Mode;
  severity?: Severity;
  enabled?: boolean;
}

export interface PolicySet {
  schema_version?: number;
  policies: Policy[];
  webhook?: string;
  updated_at?: number;
}

export interface PolicyStatus {
  policy_id: string;
  rule: string;
  head: string;
  mode: Mode;
  severity: Severity;
  status: Status;
  detail: string;
}

export interface EvalReport {
  generated_at: number;
  pass: number;
  warn: number;
  fail: number;
  statuses: PolicyStatus[];
}

export interface NeleusEvent {
  seq: number;
  timestamp: number;
  kind: string;
  prev: string;
  hash: string;
  data: Record<string, unknown>;
}

// data shape carried by `kind === "policy.violation"` events
export interface ViolationData {
  policy_id: string;
  rule: string;
  head: string;
  op: string;
  mode: Mode;
  severity: Severity;
  principal: string | null;
  enforced: boolean;
  detail: string;
}

const LS_URL = "neleus.url";
const LS_TOKEN = "neleus.token";
const DEFAULT_URL = "http://127.0.0.1:7117";

// The Rust server sets this to a non-empty string when serving same-origin.
function bootstrapToken(): string | null {
  const b = window.__NELEUS_BOOTSTRAP__;
  return typeof b === "string" && b.length > 0 ? b : null;
}

// True when the server injected the bootstrap global at all (token may be "").
function hasBootstrap(): boolean {
  return typeof window.__NELEUS_BOOTSTRAP__ === "string" && window.__NELEUS_BOOTSTRAP__.length > 0;
}

export class Conn {
  url: string;
  token: string;

  constructor() {
    if (hasBootstrap()) {
      // Served same-origin by neleus-db: target the serving origin, use the
      // injected token, and ignore any stale stored values.
      this.url = window.location.origin;
      this.token = bootstrapToken() || "";
    } else {
      this.url = localStorage.getItem(LS_URL) || DEFAULT_URL;
      this.token = localStorage.getItem(LS_TOKEN) || "";
    }
  }

  // Whether the console should auto-connect on load without manual entry.
  get autoConnect(): boolean {
    return hasBootstrap();
  }

  save(url: string, token: string) {
    this.url = url.replace(/\/$/, "");
    this.token = token;
    localStorage.setItem(LS_URL, this.url);
    localStorage.setItem(LS_TOKEN, this.token);
  }

  private async req(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<Response> {
    const headers: Record<string, string> = {};
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(this.url + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try {
        msg = ((await res.json()) as { error?: string }).error || msg;
      } catch {
        /* non-json body */
      }
      throw new Error(msg);
    }
    return res;
  }

  async json<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
    return (await (await this.req(method, path, body, signal)).json()) as T;
  }

  async blob(method: string, path: string, body?: unknown): Promise<Blob> {
    return await (await this.req(method, path, body)).blob();
  }

  health() {
    return this.json<{ ok: boolean; version: string }>("GET", "/v1/health");
  }
  summary() {
    return this.json<ComplianceSummary>("GET", "/v1/compliance/summary");
  }
  frameworks() {
    return this.json<{ frameworks: Framework[] }>("GET", "/v1/compliance/frameworks");
  }
  status(head: string, from?: number, to?: number) {
    return this.json<{ frameworks: FrameworkStatus[] }>("POST", "/v1/compliance/status", {
      head,
      ...range(from, to),
    });
  }
  check(head: string, framework: string, from?: number, to?: number) {
    return this.json<ComplianceReport>("POST", "/v1/compliance/check", {
      head,
      framework,
      ...range(from, to),
    });
  }
  reportMarkdown(head: string, framework: string, from?: number, to?: number) {
    return this.json<{ markdown: string }>("POST", "/v1/audit/report", {
      head,
      framework,
      ...range(from, to),
    });
  }
  auditQueries(head: string, from?: number, to?: number) {
    return this.json<{ records: AuditRecord[] }>("POST", "/v1/audit/queries", {
      head,
      ...range(from, to),
    });
  }
  exportBundle(head: string, from?: number, to?: number) {
    return this.blob("POST", "/v1/audit/export", { head, ...range(from, to) });
  }
  prove(commit: string, chunk: string) {
    return this.json<{ proof_cbor: string }>("POST", "/v1/proofs/chunk", {
      commit,
      chunk,
      include_content: true,
    });
  }
  verify(proof_cbor: string) {
    return this.json<{ valid: boolean; anchor?: string; error?: string }>(
      "POST",
      "/v1/proofs/verify",
      { proof_cbor },
    );
  }

  policyGet() {
    return this.json<{ policy: PolicySet }>("GET", "/v1/policy");
  }
  policySet(set: PolicySet) {
    return this.json<{ policy: PolicySet }>("POST", "/v1/policy", set);
  }
  policyEvaluate(head?: string) {
    return this.json<EvalReport>("POST", "/v1/policy/evaluate", head ? { head } : {});
  }
  // since: only events with seq > since. wait (≤30): long-poll seconds.
  events(since?: number, wait?: number, signal?: AbortSignal) {
    const q = new URLSearchParams();
    if (since !== undefined) q.set("since", String(since));
    if (wait !== undefined) q.set("wait", String(wait));
    const qs = q.toString();
    return this.json<{ events: NeleusEvent[] }>("GET", `/v1/events${qs ? `?${qs}` : ""}`, undefined, signal);
  }
}

function range(from?: number, to?: number) {
  const out: Record<string, number> = {};
  if (from !== undefined) out.from = from;
  if (to !== undefined) out.to = to;
  return out;
}

export function fmtTime(unix: number | null | undefined): string {
  if (!unix || unix > 4_000_000_000) return "—";
  return new Date(unix * 1000).toLocaleString();
}

export function download(blob: Blob, filename: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
