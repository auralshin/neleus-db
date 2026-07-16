import { useState } from "react";
import type { Conn, AuditRecord } from "../lib/api";
import { fmtTime, download } from "../lib/api";
import { short } from "./ui";

// Surface 2 — the audit log + export. Each row is a content-addressed
// QueryManifest; export produces an offline-verifiable .nelaudit bundle.
export function AuditLog({ conn, onStatus }: { conn: Conn; onStatus: (m: string, err?: boolean) => void }) {
  const [head, setHead] = useState("main");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [records, setRecords] = useState<AuditRecord[] | null>(null);

  const unix = (v: string) => (v ? Math.floor(new Date(v).getTime() / 1000) : undefined);

  async function load() {
    try {
      const d = await conn.auditQueries(head, unix(from), unix(to));
      setRecords(d.records);
      onStatus(`Loaded ${d.records.length} audit record(s).`);
    } catch (e) {
      onStatus((e as Error).message, true);
    }
  }

  async function exportBundle() {
    try {
      onStatus("Exporting bundle…");
      const blob = await conn.exportBundle(head, unix(from), unix(to));
      download(blob, `${head}-${Date.now()}.nelaudit`);
      onStatus("Bundle downloaded. Verify with `neleus-verify <file>`.");
    } catch (e) {
      onStatus((e as Error).message, true);
    }
  }

  return (
    <section className="panel glass">
      <div className="controls">
        <label>Head<input value={head} onChange={(e) => setHead(e.target.value)} spellCheck={false} /></label>
        <label>From<input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
        <label>To<input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} /></label>
        <button className="btn btn-primary btn-sm" onClick={load}>Load</button>
        <button className="btn btn-glass btn-sm" onClick={exportBundle}>Export bundle</button>
      </div>
      <p className="hint">
        Each row is a content-addressed <code>QueryManifest</code> committed to history. Export produces a
        tamper-evident bundle verifiable offline with <code>neleus-verify</code> — no Neleus, no network.
      </p>
      <div className="table-scroll">
        <table className="grid">
          <thead>
            <tr><th>When</th><th>Principal</th><th>Mode</th><th>top_k</th><th>Hits</th><th>Manifest</th></tr>
          </thead>
          <tbody>
            {records === null ? (
              <tr><td colSpan={6} className="empty">Load a head to see its audit records.</td></tr>
            ) : records.length === 0 ? (
              <tr><td colSpan={6} className="empty">No audit records in this period.</td></tr>
            ) : (
              records.map((r) => (
                <tr key={r.manifest}>
                  <td>{fmtTime(r.executed_at)}</td>
                  <td>{r.principal ?? "—"}</td>
                  <td>{r.mode}</td>
                  <td>{r.top_k}</td>
                  <td>{r.hits.length}</td>
                  <td><code className="mono">{short(r.manifest)}</code></td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
