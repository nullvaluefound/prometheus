import { useState, useMemo } from "react";
import type { Task } from "../api";
import { compactJson, fmtBytes, isRecord, isScalar, scalarText, txt } from "../format";

// Generic, text-only rendering of tool and task results. Every value is untrusted evidence, so it is shown
// as React text: no markup, no links, no images.

const MAX_FACTS = 160;
const MAX_TABLES = 8;
const MAX_ROWS = 500;
const MAX_COLUMNS = 24;
const MAX_TEXT = 200_000;
const HEXLIKE = /^(?:0x[0-9a-f]+|[a-f0-9]{32,128})$/i;

interface Pieces {
  facts: [string, string][];
  texts: { path: string; text: string }[];
  tables: { path: string; rows: Record<string, unknown>[] }[];
}

function walk(value: unknown, path: string, depth: number, out: Pieces): void {
  if (Array.isArray(value)) {
    if (value.length > 0 && value.every(isRecord)) {
      if (out.tables.length < MAX_TABLES) out.tables.push({ path: path || "rows", rows: value });
      else out.facts.push([path, `${value.length} rows`]);
      return;
    }
    if (value.every(isScalar)) {
      out.facts.push([path || "value", value.length ? value.map(scalarText).join(", ") : "(none)"]);
      return;
    }
    out.facts.push([path || "value", compactJson(value)]);
    return;
  }
  if (isRecord(value)) {
    const entries = Object.entries(value);
    if (depth >= 3) {
      out.facts.push([path, compactJson(value)]);
      return;
    }
    if (entries.length === 0 && path) out.facts.push([path, "{}"]);
    for (const [key, child] of entries) walk(child, path ? `${path}.${key}` : key, depth + 1, out);
    return;
  }
  if (typeof value === "string" && (value.includes("\n") || value.length > 160)) {
    out.texts.push({ path: path || "text", text: value.length > MAX_TEXT ? value.slice(0, MAX_TEXT) + "\n…" : value });
    return;
  }
  out.facts.push([path || "value", scalarText(value)]);
}

function pretty(value: unknown): string {
  let out: string;
  try {
    out = JSON.stringify(value, null, 2) ?? "null";
  } catch {
    out = "(unserializable result)";
  }
  return out.length > MAX_TEXT ? out.slice(0, MAX_TEXT) + "\n…" : out;
}

function Cell({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="muted">—</span>;
  if (typeof value === "string") return HEXLIKE.test(value) ? <code>{value}</code> : <span className="cell-text">{value}</span>;
  if (typeof value === "number" || typeof value === "boolean") return <span>{scalarText(value)}</span>;
  if (Array.isArray(value) && value.length === 0) return <span className="muted">—</span>;
  if (Array.isArray(value) && value.every(isScalar)) return <span className="cell-text">{value.map(scalarText).join(", ")}</span>;
  return <code className="cell-json">{compactJson(value, 600)}</code>;
}

export function DataTable({ rows, caption }: { rows: Record<string, unknown>[]; caption?: string }) {
  const columns = useMemo(() => {
    const names: string[] = [];
    for (const row of rows.slice(0, 200)) {
      for (const name of Object.keys(row)) {
        if (!names.includes(name) && names.length < MAX_COLUMNS) names.push(name);
      }
    }
    return names;
  }, [rows]);
  return (
    <div className="table-wrap">
      <table className="data">
        {caption && <caption>{caption}</caption>}
        <thead>
          <tr>
            {columns.map((name) => (
              <th key={name} scope="col">
                {name}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, MAX_ROWS).map((row, index) => (
            <tr key={index}>
              {columns.map((name) => (
                <td key={name}>
                  <Cell value={row[name]} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > MAX_ROWS && <p className="muted small">Showing the first {MAX_ROWS} of {rows.length} rows.</p>}
    </div>
  );
}

export function ResultView({ value }: { value: unknown }) {
  const pieces = useMemo(() => {
    const out: Pieces = { facts: [], texts: [], tables: [] };
    walk(value, "", 0, out);
    out.facts = out.facts.slice(0, MAX_FACTS);
    return out;
  }, [value]);
  const json = useMemo(() => pretty(value), [value]);
  const structured = pieces.facts.length + pieces.texts.length + pieces.tables.length > 0;

  return (
    <div className="result">
      {pieces.facts.length > 0 && (
        <dl className="facts">
          {pieces.facts.map(([key, text], index) => (
            <div key={`${key}-${index}`}>
              <dt>{key}</dt>
              <dd>{text}</dd>
            </div>
          ))}
        </dl>
      )}
      {pieces.texts.map(({ path, text }) => (
        <figure className="text-block" key={path}>
          <figcaption>
            {path} <span className="muted">· untrusted text</span>
          </figcaption>
          <pre className="pre pre-wrap">{text}</pre>
        </figure>
      ))}
      {pieces.tables.map(({ path, rows }) => (
        <div className="result-table" key={path}>
          <h4>
            {path} <span className="muted">({rows.length} {rows.length === 1 ? "row" : "rows"})</span>
          </h4>
          <DataTable rows={rows} />
        </div>
      ))}
      <details className="raw" open={!structured}>
        <summary>JSON</summary>
        <pre className="pre">{json}</pre>
      </details>
    </div>
  );
}

/** Kind-aware view of a finished task's result or error. */
export function TaskOutcome({ task }: { task: Task }) {
  if (task.state === "failed") {
    return <p className="note note-err">{txt(task.error) || "The task failed."}</p>;
  }
  if (task.state === "cancelled") return <p className="muted">Cancelled before it started.</p>;
  if (task.state !== "succeeded") return null;
  const result = task.result;
  if (task.kind === "report" && isRecord(result) && typeof result.markdown === "string") {
    return <ReportText markdown={result.markdown} />;
  }
  if (task.kind === "model_test" && isRecord(result) && typeof result.ok === "boolean") {
    return (
      <p className={`note ${result.ok ? "note-ok" : "note-err"}`}>
        <strong>{result.ok ? "Model reachable." : "Model test failed."}</strong> {txt(result.detail)}
      </p>
    );
  }
  if (task.kind === "ingest" && isRecord(result) && typeof result.sha256 === "string") {
    return (
      <p className="note note-ok">
        Admitted <code>{result.sha256}</code> ({fmtBytes(result.size)}).
      </p>
    );
  }
  if (result === null || result === undefined) return <p className="muted">Finished with no result.</p>;
  return <ResultView value={result} />;
}

export function ReportText({ markdown }: { markdown: string }) {
  const text = markdown.length > MAX_TEXT ? markdown.slice(0, MAX_TEXT) + "\n…" : markdown;
  return (
    <div className="report">
      <div className="report-actions">
        <span className="muted small">Markdown source, shown as plain text.</span>
        <CopyButton text={markdown} />
      </div>
      <pre className="pre pre-wrap report-text">{text}</pre>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
    window.setTimeout(() => setState("idle"), 2500);
  };
  return (
    <button type="button" className="btn-secondary btn-small" onClick={copy} aria-live="polite">
      {state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : "Copy"}
    </button>
  );
}
