import { useEffect, useState } from "react";
import type { Conn, PolicySet, Policy } from "../lib/api";
import { fmtTime } from "../lib/api";
import { ModeBadge } from "./ui";

// Surface 5 — the policy-as-code workflow. View the active PolicySet as glass
// cards, or edit the whole set as JSON and POST it back (ADMIN only).
export function Policies({ conn, onStatus }: { conn: Conn; onStatus: (m: string, err?: boolean) => void }) {
  const [set, setSet] = useState<PolicySet | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [editErr, setEditErr] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const d = await conn.policyGet();
        if (cancelled) return;
        setSet(d.policy);
        setErr(null);
        onStatus(`Loaded ${d.policy.policies.length} policy/policies.`);
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

  function startEdit() {
    if (!set) return;
    setDraft(JSON.stringify(set, null, 2));
    setEditErr(null);
    setEditing(true);
  }

  async function apply() {
    let parsed: PolicySet;
    try {
      parsed = JSON.parse(draft) as PolicySet;
    } catch (e) {
      setEditErr(`invalid JSON: ${(e as Error).message}`);
      return;
    }
    setApplying(true);
    setEditErr(null);
    try {
      const d = await conn.policySet(parsed);
      setSet(d.policy);
      setEditing(false);
      flash("applied");
      onStatus("Policy set applied.");
    } catch (e) {
      const msg = (e as Error).message;
      // 403 surfaces as the server's error string; make the admin case explicit
      setEditErr(/403|forbidden|admin|unauthor/i.test(msg) ? "admin token required to edit policies" : msg);
      onStatus(msg, true);
    } finally {
      setApplying(false);
    }
  }

  function flash(m: string) {
    setToast(m);
    setTimeout(() => setToast(null), 2200);
  }

  if (err)
    return (
      <div className="banner unknown glass">
        <div className="banner-icon">—</div>
        <div>
          <div className="banner-title">Could not load policies</div>
          <div className="banner-sub">{err}</div>
        </div>
      </div>
    );
  if (!set)
    return (
      <div className="banner unknown glass">
        <div className="banner-icon">…</div>
        <div><div className="banner-title">Loading policy set…</div></div>
      </div>
    );

  return (
    <>
      <section className="panel glass">
        <div className="policy-toolbar">
          <h3 className="panel-title" style={{ margin: 0 }}>Policy as code</h3>
          <div className="spacer" />
          {set.webhook && <span className="chip">webhook → {set.webhook}</span>}
          {set.updated_at ? <span className="policy-meta">updated <span>{fmtTime(set.updated_at)}</span></span> : null}
          <button className="btn btn-glass btn-sm" onClick={() => (editing ? setEditing(false) : startEdit())}>
            {editing ? "View cards" : "Edit as code"}
          </button>
        </div>
        <p className="hint">
          The active <code>PolicySet</code>. Edit it as JSON and apply to replace the whole set — this is the
          policy-as-code workflow. Editing requires an <code>ADMIN</code> token.
        </p>

        {editing && (
          <>
            <textarea
              className="mono"
              value={draft}
              spellCheck={false}
              onChange={(e) => setDraft(e.target.value)}
            />
            {editErr && <div className="editor-err">{editErr}</div>}
            <div className="controls" style={{ marginTop: 14, marginBottom: 0 }}>
              <button className="btn btn-primary btn-sm" onClick={apply} disabled={applying}>
                {applying ? "Applying…" : "Apply"}
              </button>
              <button className="btn btn-glass btn-sm" onClick={() => setEditing(false)}>Cancel</button>
            </div>
          </>
        )}
      </section>

      {!editing && (
        <div className="policy-grid">
          {set.policies.length === 0 ? (
            <p className="hint">No policies defined. Use “Edit as code” to add some.</p>
          ) : (
            set.policies.map((p) => <PolicyCard key={p.id} p={p} />)
          )}
        </div>
      )}

      {toast && <div className="toast">{toast}</div>}
    </>
  );
}

function PolicyCard({ p }: { p: Policy }) {
  const disabled = p.enabled === false;
  const heads = p.heads && p.heads.length > 0 ? p.heads.join(", ") : "all heads";
  return (
    <div className={`policy-card glass ${disabled ? "disabled" : ""}`}>
      <div className="policy-head">
        <span className="policy-id">{p.id}</span>
        <ModeBadge mode={p.mode} />
      </div>
      {p.description && <div className="policy-desc">{p.description}</div>}
      <div className="policy-chips">
        <span className="chip rule">{p.rule.kind}</span>
        {p.rule.kind === "retention-floor" && <span className="chip">min {p.rule.min_secs}s</span>}
        <span className="chip">{p.severity ?? "required"}</span>
        <span className="chip">{disabled ? "disabled" : "enabled"}</span>
      </div>
      <div className="policy-meta">heads: <span>{heads}</span></div>
    </div>
  );
}
