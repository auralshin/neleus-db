import { Fragment, useEffect, useState } from "react";
import type { Conn, NeleusEvent, ViolationData } from "../lib/api";
import { fmtTime } from "../lib/api";
import { EnforcedBadge, Pill } from "./ui";

// Surface 7 — the violation log. Past policy.violation events, newest first,
// each row expandable to its raw tamper-evident record.
export function Violations({ conn, onStatus }: { conn: Conn; onStatus: (m: string, err?: boolean) => void }) {
  const [events, setEvents] = useState<NeleusEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [enforcedOnly, setEnforcedOnly] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  // undefined = not checked. Never collapse that into false.
  const [chainOk, setChainOk] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Compliance read: worth a chain walk. Monitor's poll must not ask.
        const { events: evs, chain_verified } = await conn.events(undefined, undefined, undefined, true);
        if (cancelled) return;
        setEvents(evs);
        setChainOk(chain_verified);
        const n = evs.filter((e) => e.kind === "policy.violation").length;
        onStatus(`Loaded ${n} violation event(s).`);
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
          <div className="banner-title">Could not load events</div>
          <div className="banner-sub">{err}</div>
        </div>
      </div>
    );

  const rows = (events ?? [])
    .filter((e) => e.kind === "policy.violation")
    .sort((a, b) => b.seq - a.seq)
    .filter((e) => !enforcedOnly || (e.data as unknown as ViolationData).enforced);

  return (
    <section className="panel glass">
      <div className="policy-toolbar">
        <h3 className="panel-title" style={{ margin: 0 }}>Violations</h3>
        <Pill status={chainOk === undefined ? "none" : chainOk ? "pass" : "fail"}>
          {chainOk === undefined ? "chain unchecked" : chainOk ? "chain intact" : "CHAIN BROKEN"}
        </Pill>
        <div className="spacer" />
        <div className="filter-toggle">
          <button className={enforcedOnly ? "" : "active"} onClick={() => setEnforcedOnly(false)}>all</button>
          <button className={enforcedOnly ? "active" : ""} onClick={() => setEnforcedOnly(true)}>enforced only</button>
        </div>
      </div>
      <p className="hint">
        Each row is a <code>policy.violation</code> event. The <code>hash</code>/<code>prev</code> fields chain
        every event together; the badge above is the server’s re-check. Confirm it independently with
        <code>neleus-verify</code>.
      </p>

      <div className="table-scroll">
        <table className="grid">
          <thead>
            <tr><th>When</th><th>Policy</th><th>Rule</th><th>Head</th><th>Op</th><th>Principal</th><th>Enforced</th><th>Detail</th></tr>
          </thead>
          <tbody>
            {events === null ? (
              <tr><td colSpan={8} className="empty">Loading…</td></tr>
            ) : rows.length === 0 ? (
              <tr><td colSpan={8} className="empty">No violations{enforcedOnly ? " enforced" : ""} yet.</td></tr>
            ) : (
              rows.map((e) => {
                const d = e.data as unknown as ViolationData;
                const expanded = open === e.hash;
                return (
                  <Fragment key={e.hash}>
                    <tr className="row-click" onClick={() => setOpen(expanded ? null : e.hash)}>
                      <td>{fmtTime(e.timestamp)}</td>
                      <td>{d.policy_id}</td>
                      <td><code className="mono">{d.rule}</code></td>
                      <td><code className="mono">{d.head}</code></td>
                      <td>{d.op}</td>
                      <td>{d.principal ?? "—"}</td>
                      <td><EnforcedBadge enforced={d.enforced} /></td>
                      <td>{d.detail}</td>
                    </tr>
                    {expanded && (
                      <tr>
                        <td colSpan={8}>
                          <pre className="raw-json">{JSON.stringify(e, null, 2)}</pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
