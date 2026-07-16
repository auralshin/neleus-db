import { useEffect, useState } from "react";
import type { Conn, ComplianceSummary, FrameworkStatus } from "../lib/api";
import { fmtTime } from "../lib/api";
import { Card, Panel, Pill, statusWord } from "./ui";

// Surface 1 — the CCO's morning view. One load-bearing signal (chain intact),
// then per-jurisdiction regulatory status, agent activity, and retention.
export function Overview({ conn, onStatus }: { conn: Conn; onStatus: (m: string, err?: boolean) => void }) {
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [statuses, setStatuses] = useState<FrameworkStatus[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const s = await conn.summary();
        if (cancelled) return;
        setSummary(s);
        const head = s.heads[0]?.name;
        if (head) {
          const st = await conn.status(head);
          if (!cancelled) setStatuses(st.frameworks);
        }
        onStatus(`Loaded ${s.heads.length} head(s).`);
      } catch (e) {
        if (!cancelled) {
          setErr((e as Error).message);
          onStatus((e as Error).message, true);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [conn]);

  if (err)
    return (
      <div className="banner unknown glass">
        <div className="banner-icon">—</div>
        <div>
          <div className="banner-title">Could not load</div>
          <div className="banner-sub">{err}</div>
        </div>
      </div>
    );
  if (!summary)
    return (
      <div className="banner unknown glass">
        <div className="banner-icon">…</div>
        <div>
          <div className="banner-title">Loading compliance state…</div>
        </div>
      </div>
    );

  const heads = summary.heads;
  const broken = heads.filter((h) => h.chain.intact === false);
  const anchored = heads.filter((h) => h.chain.length > 0);
  const totalRetr = heads.reduce((n, h) => n + h.retrievals_30d, 0);
  const principals = new Set<string>();
  heads.forEach((h) => h.principals_30d.forEach((p) => principals.add(p)));

  const bannerState = broken.length > 0 ? "bad" : anchored.length === 0 ? "warn" : "ok";
  const bannerTitle =
    broken.length > 0
      ? `Chain broken on ${broken.length} head${broken.length > 1 ? "s" : ""}`
      : anchored.length === 0
        ? "No checkpoint chains anchored"
        : "All checkpoint chains intact";
  const bannerSub =
    broken.length > 0
      ? "Tamper-evidence violated. Investigate immediately."
      : anchored.length === 0
        ? "Run `checkpoint new --sign-key` to anchor history."
        : `${anchored.length} head${anchored.length > 1 ? "s" : ""} anchored and verified.`;

  // group regulatory status by jurisdiction
  const byRegion = new Map<string, FrameworkStatus[]>();
  (statuses ?? []).forEach((f) => {
    const list = byRegion.get(f.jurisdiction) ?? [];
    list.push(f);
    byRegion.set(f.jurisdiction, list);
  });

  return (
    <>
      <div className={`banner ${bannerState} glass`}>
        <div className="banner-icon">{broken.length > 0 ? "✕" : anchored.length === 0 ? "!" : "✓"}</div>
        <div>
          <div className="banner-title">{bannerTitle}</div>
          <div className="banner-sub">{bannerSub}</div>
        </div>
      </div>

      <div className="metrics">
        <Card num={totalRetr.toLocaleString()} label="Signed retrievals · 30d" note={`${anchored.length > 0 ? "100%" : "0%"} chain-verified`} />
        <Card num={principals.size} label="Active principals" />
        <Card num={anchored.length} label="Chains anchored" />
        <Card
          num={summary.retention_min_secs ? `${Math.round(summary.retention_min_secs / 86400)}d` : "off"}
          label="Retention floor"
          note={summary.encryption_enabled ? "encrypted at rest" : "no encryption"}
          tone={summary.encryption_enabled ? undefined : "warn"}
        />
      </div>

      <div className="two-col">
        <Panel title="Regulatory framework status">
          {statuses === null ? (
            <p className="hint">No head to evaluate.</p>
          ) : (
            [...byRegion.entries()].map(([region, fws]) => (
              <div className="reg-group" key={region}>
                <div className="reg-region">{region}</div>
                {fws.map((f) => (
                  <div className="reg-row" key={f.id}>
                    <span>{f.name}</span>
                    <Pill status={f.overall}>{statusWord(f.overall)}</Pill>
                  </div>
                ))}
              </div>
            ))
          )}
        </Panel>

        <Panel title="Heads">
          <div className="table-scroll">
            <table className="grid">
              <thead>
                <tr><th>Head</th><th>Chain</th><th>Checkpoints</th><th>Retrievals 30d</th><th>Last</th></tr>
              </thead>
              <tbody>
                {heads.length === 0 ? (
                  <tr><td colSpan={5} className="empty">No heads yet.</td></tr>
                ) : (
                  heads.map((h) => (
                    <tr key={h.name}>
                      <td><code className="mono">{h.name}</code></td>
                      <td>
                        {h.chain.intact === true ? <Pill status="pass">intact</Pill>
                          : h.chain.intact === false ? <Pill status="fail">broken</Pill>
                            : <Pill status="none">none</Pill>}
                      </td>
                      <td>{h.chain.length ? `${h.chain.length} (${h.chain.signed} signed)` : "—"}</td>
                      <td>{h.retrievals_30d.toLocaleString()}</td>
                      <td>{fmtTime(h.last_retrieval_at)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  );
}
