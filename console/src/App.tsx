import { useEffect, useMemo, useRef, useState } from "react";
import "./App.css";
import { Conn } from "./lib/api";
import { Trident, GitHubIcon } from "./components/icons";
import { REPO } from "./links";
import { Overview } from "./components/Overview";
import { AuditLog } from "./components/AuditLog";
import { Reports } from "./components/Reports";
import { Inspector } from "./components/Inspector";
import { Policies } from "./components/Policies";
import { Monitor } from "./components/Monitor";
import { Violations } from "./components/Violations";

type View = "overview" | "audit" | "report" | "inspect" | "policies" | "monitor" | "violations";
type ConnState = "off" | "on" | "err";

const TABS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "audit", label: "Audit log" },
  { id: "report", label: "Reports" },
  { id: "inspect", label: "Inspector" },
  { id: "policies", label: "Policies" },
  { id: "monitor", label: "Monitor" },
  { id: "violations", label: "Violations" },
];

export default function App() {
  const conn = useMemo(() => new Conn(), []);
  const [url, setUrl] = useState(conn.url);
  const [token, setToken] = useState(conn.token);
  const [connState, setConnState] = useState<ConnState>("off");
  const [connLabel, setConnLabel] = useState("disconnected");
  const [view, setView] = useState<View>("overview");
  const [status, setStatusRaw] = useState("Enter a server URL and token to connect.");
  const [statusErr, setStatusErr] = useState(false);
  // remount the active view on (re)connect so it refetches
  const [epoch, setEpoch] = useState(0);
  const autoTried = useRef(false);

  const onStatus = (m: string, err = false) => {
    setStatusRaw(m);
    setStatusErr(err);
  };

  async function doConnect(targetUrl: string, targetToken: string) {
    conn.save(targetUrl, targetToken);
    try {
      const h = await conn.health();
      setConnState("on");
      setConnLabel(`connected · v${h.version}`);
      setEpoch((n) => n + 1);
      onStatus("Connected.");
    } catch (err) {
      setConnState("err");
      setConnLabel("failed");
      onStatus((err as Error).message, true);
    }
  }

  function connect(e: React.FormEvent) {
    e.preventDefault();
    void doConnect(url, token);
  }

  // Served same-origin by neleus-db: connect immediately with origin + token.
  useEffect(() => {
    if (autoTried.current || !conn.autoConnect) return;
    autoTried.current = true;
    void doConnect(conn.url, conn.token);
  }, [conn]);

  return (
    <div className="console">
      <header className="nav">
        <div className="nav-inner glass">
          <a className="brand" href={REPO} target="_blank" rel="noreferrer" aria-label="Neleus DB — repository">
            <Trident />
            <span className="brand-name">
              NELEUS<span>CONSOLE</span>
            </span>
          </a>

          <form className="conn" onSubmit={connect}>
            <input
              className="conn-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://127.0.0.1:7117"
              spellCheck={false}
              aria-label="Server URL"
            />
            <input
              className="conn-input"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              type="password"
              placeholder="nlk_… token"
              aria-label="Bearer token"
            />
            <button type="submit" className="btn btn-primary btn-sm">Connect</button>
            <span className={`conn-state ${connState}`}>{connLabel}</span>
          </form>

          <a className="nav-gh" href={REPO} target="_blank" rel="noreferrer" aria-label="GitHub">
            <GitHubIcon size={17} />
          </a>
        </div>
      </header>

      <nav className="tabs-bar">
        <div className="tabs glass">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`tab ${view === t.id ? "active" : ""}`}
              onClick={() => setView(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
      </nav>

      <main className="console-main">
        {connState !== "on" ? (
          <div className="banner unknown glass">
            <div className="banner-icon">—</div>
            <div>
              <div className="banner-title">Not connected</div>
              <div className="banner-sub">
                Start a server with <code>neleus-db serve --cors-origin http://localhost:5173</code>, mint a token
                with <code>auth add-key</code>, then connect above. When neleus-db serves this console on loopback it
                connects automatically.
              </div>
            </div>
          </div>
        ) : (
          <div key={`${epoch}-${view}`}>
            {view === "overview" && <Overview conn={conn} onStatus={onStatus} />}
            {view === "audit" && <AuditLog conn={conn} onStatus={onStatus} />}
            {view === "report" && <Reports conn={conn} onStatus={onStatus} />}
            {view === "inspect" && <Inspector conn={conn} onStatus={onStatus} />}
            {view === "policies" && <Policies conn={conn} onStatus={onStatus} />}
            {view === "monitor" && <Monitor conn={conn} onStatus={onStatus} />}
            {view === "violations" && <Violations conn={conn} onStatus={onStatus} />}
          </div>
        )}
      </main>

      <footer className="console-foot">
        <span className={statusErr ? "err" : ""}>{status}</span>
        <span className="foot-right">Neleus Console · <code>neleus-db serve</code></span>
      </footer>
    </div>
  );
}
