import { useEffect, useMemo, useState } from "react";
import type { Conn, Framework, ComplianceReport } from "../lib/api";
import { download } from "../lib/api";
import { Markdown } from "../lib/markdown";
import { Pill, statusWord } from "./ui";

// Surface 3 — the regulatory report generator. Pick a jurisdiction + law,
// see live checks, render and download the formatted report.
export function Reports({ conn, onStatus }: { conn: Conn; onStatus: (m: string, err?: boolean) => void }) {
  const [head, setHead] = useState("main");
  const [frameworks, setFrameworks] = useState<Framework[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [markdown, setMarkdown] = useState<string>("");

  useEffect(() => {
    conn
      .frameworks()
      .then((d) => {
        setFrameworks(d.frameworks);
        if (d.frameworks[0]) setSelected(d.frameworks[0].id);
      })
      .catch((e) => onStatus((e as Error).message, true));
  }, [conn]);

  // group frameworks by jurisdiction for the selector
  const grouped = useMemo(() => {
    const m = new Map<string, Framework[]>();
    frameworks.forEach((f) => {
      const list = m.get(f.jurisdiction) ?? [];
      list.push(f);
      m.set(f.jurisdiction, list);
    });
    return [...m.entries()];
  }, [frameworks]);

  async function generate() {
    if (!selected) return;
    try {
      const [r, md] = await Promise.all([
        conn.check(head, selected),
        conn.reportMarkdown(head, selected),
      ]);
      setReport(r);
      setMarkdown(md.markdown);
      onStatus(`Report generated for ${r.name}.`);
    } catch (e) {
      onStatus((e as Error).message, true);
    }
  }

  return (
    <div className="reports">
      <div className="reports-left glass">
        <div className="step">1 — Head &amp; framework</div>
        <input value={head} onChange={(e) => setHead(e.target.value)} placeholder="head (e.g. main)" spellCheck={false} />
        <div className="framework-list">
          {grouped.map(([jurisdiction, fws]) => (
            <div key={jurisdiction}>
              <div className="reg-region">{jurisdiction}</div>
              {fws.map((f) => (
                <button
                  key={f.id}
                  className={`framework-card ${selected === f.id ? "active" : ""}`}
                  onClick={() => setSelected(f.id)}
                >
                  <div className="fw-name">{f.name}</div>
                  <div className="fw-cite">{f.citation}</div>
                </button>
              ))}
            </div>
          ))}
        </div>
        <button className="btn btn-primary report-generate" onClick={generate}>Generate report</button>
      </div>

      <div className="reports-right glass">
        {!report ? (
          <p className="hint">Select a framework and generate a report to map this head's audit evidence to its requirements.</p>
        ) : (
          <>
            <div className="report-head">
              <div>
                <div className="report-title">{report.name}</div>
                <div className="report-sub">{report.jurisdiction} · {report.citation} · {report.retrievals} retrievals</div>
              </div>
              <div className="report-actions">
                <Pill status={report.overall}>{statusWord(report.overall)}</Pill>
                <button
                  className="btn btn-glass btn-sm"
                  onClick={() => download(new Blob([markdown], { type: "text/markdown" }), `${report.framework}-report.md`)}
                >
                  Download .md
                </button>
              </div>
            </div>

            <div className="checks">
              {report.checks.map((c) => (
                <div className="check-row" key={c.id}>
                  <span className={`check-dot ${c.status}`} />
                  <div className="check-body">
                    <div className="check-label">{c.label} <span className="check-sev">{c.severity}</span></div>
                    <div className="check-detail">{c.detail}</div>
                  </div>
                  <Pill status={c.status}>{statusWord(c.status)}</Pill>
                </div>
              ))}
            </div>

            <details className="report-md">
              <summary>Full report document</summary>
              <Markdown source={markdown} />
            </details>
          </>
        )}
      </div>
    </div>
  );
}
