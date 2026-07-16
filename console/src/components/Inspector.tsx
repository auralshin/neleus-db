import { useState } from "react";
import type { Conn } from "../lib/api";

// Surface 4 — the engineer's trace tool. Enter commit + chunk, get the proof
// chain and a verification. The same bundle verifies offline.
export function Inspector({ conn, onStatus }: { conn: Conn; onStatus: (m: string, err?: boolean) => void }) {
  const [commit, setCommit] = useState("");
  const [chunk, setChunk] = useState("");
  const [result, setResult] = useState<{ valid: boolean; anchor?: string; error?: string } | null>(null);

  async function trace() {
    if (!commit || !chunk) {
      onStatus("Enter both a commit and a chunk hash.", true);
      return;
    }
    try {
      onStatus("Building proof…");
      const { proof_cbor } = await conn.prove(commit.trim(), chunk.trim());
      const verdict = await conn.verify(proof_cbor);
      setResult(verdict);
      onStatus(verdict.valid ? "Proof verified." : "Proof INVALID.", !verdict.valid);
    } catch (e) {
      setResult({ valid: false, error: (e as Error).message });
      onStatus((e as Error).message, true);
    }
  }

  const steps = [
    ["Retrieval ran against commit", commit || "—"],
    ["Reachable via first-parent ancestry to the introducing commit", 'blake3("commit:" ‖ bytes)'],
    [`Manifest (${result?.anchor ?? "—"}) listed by that commit`, 'blake3("manifest:" ‖ bytes)'],
    ["Chunk referenced by the manifest", chunk || "—"],
    ["Chunk content hashes to the chunk id", 'blake3("blob:" ‖ content)'],
  ];

  return (
    <section className="panel glass">
      <div className="controls">
        <label>Commit<input value={commit} onChange={(e) => setCommit(e.target.value)} placeholder="64-hex commit hash" spellCheck={false} /></label>
        <label>Chunk<input value={chunk} onChange={(e) => setChunk(e.target.value)} placeholder="64-hex chunk hash" spellCheck={false} /></label>
        <button className="btn btn-primary btn-sm" onClick={trace}>Prove &amp; verify</button>
      </div>
      <p className="hint">
        Fetches the proof bundle for a retrieved chunk and verifies it server-side. The same bundle verifies
        offline — no Neleus dependency.
      </p>

      {result && (
        <div className="proof">
          <div className={`proof-verdict ${result.valid ? "ok" : "bad"}`}>
            <span className="big">{result.valid ? "✓" : "✕"}</span>
            <div>
              <div className="verdict-word">{result.valid ? "VERIFIED" : "INVALID"}</div>
              <div className="hint">
                {result.valid
                  ? <>Anchored by a <code>{result.anchor}</code> manifest. Tampering with any link breaks the chain.</>
                  : result.error}
              </div>
            </div>
          </div>
          {result.valid && (
            <ol className="chain-steps">
              {steps.map(([label, val], i) => (
                <li key={i}>
                  <div className="chain-k">{label}</div>
                  <div className="chain-v">{val}</div>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </section>
  );
}
