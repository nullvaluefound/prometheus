import { useId, useRef, useState, type FormEvent } from "react";
import { ApiError, COMPLETENESS, api, type Artifact, type Completeness, type Policy, type Provenance, type Task } from "../../api";
import { TaskOutcome } from "../../components/ResultView";
import { Empty, Note, Panel, TaskChip, Time } from "../../components/ui";
import { DIGEST, MAX_UPLOAD_BYTES, SOURCE_LABEL, SOURCE_PATTERN, fmtBytes, fmtCount, isRecord, list, short, txt } from "../../format";
import { errorMessage, isTerminal, useTask } from "../../hooks";
import type { CaseContext } from "../CaseView";

const TOO_LARGE =
  "The upload is larger than the Forge accepts. The Forge limit is 128 MiB, and the proxy in front of it may cap uploads lower.";

export function ArtifactsTab({
  ctx,
  policy,
  onSummary,
  onTools,
}: {
  ctx: CaseContext;
  policy: Policy | undefined;
  onSummary: (artifact: string) => void;
  onTools: (artifact: string) => void;
}) {
  const ledger = ctx.detail.ledger;
  const artifacts = list<Artifact>(ledger?.artifacts).filter((item) => isRecord(item) && DIGEST.test(txt(item.sha256)));
  const canSummarize = !policy || list<{ name: string }>(policy.tools).some((tool) => tool.name === "artifact_summary");

  return (
    <div className="stack">
      <UploadPanel ctx={ctx} />
      <Panel title="Ledger artifacts">
        {!ledger ? (
          <Note tone="warn">The evidence ledger is unavailable. Check the Docker engine and run verify.</Note>
        ) : artifacts.length === 0 ? (
          <Empty>No artifacts admitted yet. Upload one above.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="data wide">
              <thead>
                <tr>
                  <th scope="col">SHA-256</th>
                  <th scope="col" className="num">
                    Size
                  </th>
                  <th scope="col">Provenance</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {artifacts.map((item) => (
                  <tr key={item.sha256}>
                    <td className="hash-cell">
                      <code>{item.sha256}</code>
                    </td>
                    <td className="num nowrap" title={typeof item.size === "number" ? `${fmtCount(item.size)} bytes` : undefined}>
                      {fmtBytes(item.size)}
                    </td>
                    <td>
                      <ProvenanceList entries={list<Provenance>(item.provenance)} />
                    </td>
                    <td>
                      <div className="row-actions">
                        {canSummarize && (
                          <button
                            type="button"
                            className="btn-small"
                            disabled={ctx.inactive !== null}
                            onClick={() => onSummary(item.sha256)}
                            aria-label={`Summarize ${short(item.sha256)}`}
                          >
                            Summary
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn-secondary btn-small"
                          disabled={ctx.inactive !== null}
                          onClick={() => onTools(item.sha256)}
                          aria-label={`Open tools for ${short(item.sha256)}`}
                        >
                          Tools
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {ctx.inactive && artifacts.length > 0 && <p className="muted small">{ctx.inactive}</p>}
      </Panel>
    </div>
  );
}

function ProvenanceList({ entries }: { entries: Provenance[] }) {
  const shown = entries.filter(isRecord).slice(0, 6);
  if (shown.length === 0) return <span className="muted">—</span>;
  return (
    <ul className="provenance">
      {shown.map((entry, index) => (
        <li key={index}>
          <span className="cell-text">{txt(entry.source) || "unknown source"}</span>
          <span className="muted"> · {txt(entry.completeness) || "unknown"}</span>
          {entry.parent && (
            <span className="muted small provenance-parent">
              from <code title={txt(entry.parent)}>{short(entry.parent, 16)}</code>
              {txt(entry.relation) && <> ({txt(entry.relation)})</>}
            </span>
          )}
          {entry.acquired_utc && (
            <span className="muted small provenance-time">
              <Time utc={entry.acquired_utc} />
            </span>
          )}
        </li>
      ))}
      {entries.length > shown.length && <li className="muted small">and {entries.length - shown.length} more</li>}
    </ul>
  );
}

function UploadPanel({ ctx }: { ctx: CaseContext }) {
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState("");
  const [completeness, setCompleteness] = useState<Completeness>("complete");
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [started, setStarted] = useState<Task | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const fileHint = useId();
  const sourceHint = useId();
  const tracked = useTask(started?.id ?? null, {
    initial: started,
    onSettled: (task) => {
      if (task.state === "succeeded") ctx.reload();
    },
  });
  const task = tracked.task ?? started;
  const pending = uploading || (task !== null && !isTerminal(task.state));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!file) {
      setError("Choose a file to upload.");
      return;
    }
    if (file.size === 0) {
      setError("The file is empty.");
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setError(`This file is ${fmtBytes(file.size)}. ${TOO_LARGE}`);
      return;
    }
    const label = source.trim();
    if (!SOURCE_LABEL.test(label)) {
      setError("The source label must start with a letter or digit and use only letters, digits, spaces and _ . / ( ) , -, up to 160 characters.");
      return;
    }
    setUploading(true);
    try {
      const reply = await api.uploadArtifact(ctx.id, file, label, completeness);
      setStarted(reply.task);
      setFile(null);
      if (fileRef.current) fileRef.current.value = "";
    } catch (failure) {
      if (failure instanceof ApiError && failure.status === 413) setError(TOO_LARGE);
      else if (failure instanceof ApiError && failure.status === 0)
        setError(`${failure.message} A proxy that caps uploads can also drop the connection on a large file.`);
      else setError(errorMessage(failure));
    } finally {
      setUploading(false);
    }
  };

  return (
    <Panel title="Admit an artifact">
      {ctx.inactive && <Note tone="warn">{ctx.inactive}</Note>}
      <form className="stack-sm" onSubmit={submit} noValidate>
        {error && (
          <p className="note note-err" role="alert">
            {error}
          </p>
        )}
        <div className="form-grid">
          <label className="field">
            <span>File</span>
            <input
              ref={fileRef}
              type="file"
              name="file"
              required
              disabled={ctx.inactive !== null || pending}
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              aria-describedby={fileHint}
            />
            <span className="hint" id={fileHint}>
              Up to 128 MiB. The bytes are hashed and stored as evidence, never executed.
              {file && ` Selected: ${fmtBytes(file.size)}.`}
            </span>
          </label>
          <label className="field">
            <span>Source label</span>
            <input
              name="source"
              value={source}
              onChange={(event) => setSource(event.target.value)}
              pattern={SOURCE_PATTERN}
              maxLength={160}
              required
              placeholder="e.g. IR-2291 mailbox export"
              autoComplete="off"
              disabled={ctx.inactive !== null || pending}
              aria-describedby={sourceHint}
            />
            <span className="hint" id={sourceHint}>
              Where the bytes came from. Recorded in the ledger provenance.
            </span>
          </label>
          <label className="field">
            <span>Completeness</span>
            <select
              name="completeness"
              value={completeness}
              onChange={(event) => setCompleteness(event.target.value as Completeness)}
              disabled={ctx.inactive !== null || pending}
            >
              {COMPLETENESS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
        </div>
        <div className="form-actions">
          <button type="submit" disabled={ctx.inactive !== null || pending}>
            {uploading ? "Uploading…" : task && !isTerminal(task.state) ? "Admitting…" : "Upload"}
          </button>
          <span className="muted small">The proxy in front of the Forge may cap uploads below 128 MiB.</span>
        </div>
      </form>
      {task && (
        <div className="stack-sm upload-status" aria-live="polite">
          <p className="task-line">
            <TaskChip state={task.state} />
            <span>{txt(task.title) || "Ingest"}</span>
            <Time utc={task.finished_utc ?? task.created_utc} relative />
          </p>
          {tracked.error && !isTerminal(task.state) && <p className="muted small">Status check failed: {tracked.error}</p>}
          <TaskOutcome task={task} />
        </div>
      )}
    </Panel>
  );
}
