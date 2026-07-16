// Minimal markdown -> React for the generated report bodies. Handles the
// subset the engine emits: headings, tables, lists, fenced code, bold, inline
// code. No dependency, no dangerouslySetInnerHTML.

import { Fragment, type ReactNode } from "react";

export function Markdown({ source }: { source: string }) {
  return <div className="md">{render(source)}</div>;
}

function render(md: string): ReactNode[] {
  const lines = md.split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  let key = 0;
  const k = () => `n${key++}`;

  while (i < lines.length) {
    const line = lines[i];

    // table
    if (/^\|/.test(line) && /^\|[\s:|-]+\|?\s*$/.test(lines[i + 1] || "")) {
      const rows: string[] = [];
      while (i < lines.length && /^\|/.test(lines[i])) rows.push(lines[i++]);
      out.push(<Table key={k()} rows={rows} />);
      continue;
    }
    // fenced code
    if (/^```/.test(line)) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out.push(
        <pre key={k()}>
          <code>{buf.join("\n")}</code>
        </pre>,
      );
      continue;
    }
    // lists
    if (/^- /.test(line)) {
      const items: ReactNode[] = [];
      while (i < lines.length && /^- /.test(lines[i])) {
        items.push(<li key={k()}>{inline(lines[i].slice(2))}</li>);
        i++;
      }
      out.push(<ul key={k()}>{items}</ul>);
      continue;
    }
    if (/^### /.test(line)) out.push(<h3 key={k()}>{inline(line.slice(4))}</h3>);
    else if (/^## /.test(line)) out.push(<h2 key={k()}>{inline(line.slice(3))}</h2>);
    else if (/^# /.test(line)) out.push(<h1 key={k()}>{inline(line.slice(2))}</h1>);
    else if (line.trim() === "") {
      /* skip blank */
    } else out.push(<p key={k()}>{inline(line)}</p>);
    i++;
  }
  return out;
}

function Table({ rows }: { rows: string[] }) {
  const cells = (r: string) =>
    r.replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
  const head = cells(rows[0]);
  const body = rows.slice(2).map(cells);
  return (
    <table>
      <thead>
        <tr>{head.map((h, i) => <th key={i}>{inline(h)}</th>)}</tr>
      </thead>
      <tbody>
        {body.map((r, i) => (
          <tr key={i}>{r.map((c, j) => <td key={j}>{inline(c)}</td>)}</tr>
        ))}
      </tbody>
    </table>
  );
}

function inline(s: string): ReactNode {
  // split on `code` and **bold**, keep delimiters
  const parts = s.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((p, i) => {
    if (/^`.+`$/.test(p)) return <code key={i}>{p.slice(1, -1)}</code>;
    if (/^\*\*.+\*\*$/.test(p)) return <strong key={i}>{p.slice(2, -2)}</strong>;
    return <Fragment key={i}>{p}</Fragment>;
  });
}
