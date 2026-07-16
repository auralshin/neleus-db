import { useEffect, useRef, useState } from "react";
import type { Conn, EvalReport, PolicyStatus, NeleusEvent, ViolationData } from "../lib/api";
import { fmtTime } from "../lib/api";
import { Pill, ModeBadge, EnforcedBadge } from "./ui";

const EVAL_EVERY_MS = 10_000;
const POLL_WAIT_SECS = 25;
const BACKOFF_MS = 3_000;
const MAX_FEED = 200;

type FeedState = "live" | "err" | "off";

// Surface 6 — the live operational surface. Periodic policy evaluation plus a
// long-polled violation feed.
export function Monitor({ conn, onStatus }: { conn: Conn; onStatus: (m: string, err?: boolean) => void }) {
  const [report, setReport] = useState<EvalReport | null>(null);
  const [feed, setFeed] = useState<NeleusEvent[]>([]);
  const [feedState, setFeedState] = useState<FeedState>("off");

  // ---- periodic evaluation ----
  useEffect(() => {
    let cancelled = false;
    async function run() {
      try {
        const r = await conn.policyEvaluate();
        if (!cancelled) setReport(r);
      } catch (e) {
        if (!cancelled) onStatus((e as Error).message, true);
      }
    }
    void run();
    const id = setInterval(run, EVAL_EVERY_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [conn]);

  // ---- long-poll live feed ----
  // Establish a baseline `since` from the latest event, then loop: each
  // events(since, wait) blocks server-side up to `wait`s for new events.
  // On return we prepend them, advance `since`, and immediately re-poll.
  // A mounted flag + AbortController tears the loop down on unmount; fetch
  // errors back off so a disconnect doesn't busy-loop.
  const sinceRef = useRef(0);
  useEffect(() => {
    let mounted = true;
    const ctrl = new AbortController();
    const sleep = (ms: number) =>
      new Promise<void>((res) => {
        const t = setTimeout(res, ms);
        ctrl.signal.addEventListener("abort", () => { clearTimeout(t); res(); }, { once: true });
      });

    async function loop() {
      // baseline: latest seq, so we only stream events from now on
      try {
        const { events } = await conn.events(undefined, undefined, ctrl.signal);
        if (!mounted) return;
        sinceRef.current = events.reduce((m, e) => Math.max(m, e.seq), 0);
        setFeedState("live");
      } catch {
        if (!mounted) return;
        if (ctrl.signal.aborted) return;
        setFeedState("err");
        await sleep(BACKOFF_MS);
      }

      while (mounted && !ctrl.signal.aborted) {
        try {
          const { events } = await conn.events(sinceRef.current, POLL_WAIT_SECS, ctrl.signal);
          if (!mounted) return;
          setFeedState("live");
          if (events.length > 0) {
            sinceRef.current = events.reduce((m, e) => Math.max(m, e.seq), sinceRef.current);
            const newest = [...events].sort((a, b) => b.seq - a.seq);
            setFeed((cur) => [...newest, ...cur].slice(0, MAX_FEED));
          }
        } catch {
          if (!mounted || ctrl.signal.aborted) return;
          setFeedState("err");
          await sleep(BACKOFF_MS);
        }
      }
    }
    void loop();
    return () => {
      mounted = false;
      ctrl.abort();
    };
  }, [conn]);

  const statuses = report
    ? [...report.statuses].sort((a, b) => rank(b.status) - rank(a.status))
    : [];
  const violations = feed.filter((e) => e.kind === "policy.violation");

  return (
    <>
      <div className="monitor-grid">
        <section className="panel glass">
          <h3 className="panel-title">Policy evaluation</h3>
          <div className="tiles">
            <div className="tile glass pass"><div className="tile-num">{report?.pass ?? "—"}</div><div className="tile-label">pass</div></div>
            <div className="tile glass warn"><div className="tile-num">{report?.warn ?? "—"}</div><div className="tile-label">warn</div></div>
            <div className="tile glass fail"><div className="tile-num">{report?.fail ?? "—"}</div><div className="tile-label">fail</div></div>
          </div>
          <p className="hint" style={{ marginBottom: 8 }}>
            Re-evaluated every 10s against the current head.
            {report ? ` Generated ${fmtTime(report.generated_at)}.` : ""}
          </p>
          <div className="table-scroll">
            <table className="grid">
              <thead>
                <tr><th>Status</th><th>Policy</th><th>Rule</th><th>Head</th><th>Mode</th><th>Detail</th></tr>
              </thead>
              <tbody>
                {!report ? (
                  <tr><td colSpan={6} className="empty">Evaluating…</td></tr>
                ) : statuses.length === 0 ? (
                  <tr><td colSpan={6} className="empty">No policies to evaluate.</td></tr>
                ) : (
                  statuses.map((s: PolicyStatus, i) => (
                    <tr key={`${s.policy_id}-${s.head}-${i}`}>
                      <td><Pill status={s.status}>{s.status}</Pill></td>
                      <td>{s.policy_id}</td>
                      <td><code className="mono">{s.rule}</code></td>
                      <td><code className="mono">{s.head}</code></td>
                      <td><ModeBadge mode={s.mode} /></td>
                      <td>{s.detail}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel glass">
          <div className="feed-head">
            <h3 className="panel-title" style={{ margin: 0 }}>Live violations</h3>
            <span className={`live-dot ${feedState}`}>
              {feedState === "live" ? "streaming" : feedState === "err" ? "reconnecting" : "connecting"}
            </span>
          </div>
          {violations.length === 0 ? (
            <p className="hint">No violations since you opened this view. The feed long-polls and updates in real time.</p>
          ) : (
            <div className="feed">
              {violations.map((e) => {
                const d = e.data as unknown as ViolationData;
                return (
                  <div key={e.hash} className={`feed-item ${d.enforced ? "enforced" : ""}`}>
                    <div className="feed-item-top">
                      <span className="feed-pid">{d.policy_id}</span>
                      <EnforcedBadge enforced={d.enforced} />
                      <span className="feed-time">{fmtTime(e.timestamp)}</span>
                    </div>
                    <div className="feed-item-top" style={{ marginTop: 5 }}>
                      <span className="feed-rule">{d.rule}</span>
                      <span className="feed-rule">· head <code className="mono">{d.head}</code></span>
                    </div>
                    <div className="feed-detail">{d.detail}</div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </>
  );
}

function rank(s: "pass" | "warn" | "fail"): number {
  return s === "fail" ? 2 : s === "warn" ? 1 : 0;
}
