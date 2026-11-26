import { useId, useState, type FormEvent } from "react";
import { api, type Task } from "../api";
import { CASE_ID, CASE_ID_PATTERN } from "../format";
import { errorMessage, isTerminal, useTask } from "../hooks";
import { caseHref } from "../router";
import { Dialog, TaskChip } from "./ui";

const TITLE_MAX = 120;

export function NewCaseDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  return (
    <Dialog open={open} title="New case" onClose={onClose}>
      <NewCaseForm onClose={onClose} onCreated={onCreated} />
    </Dialog>
  );
}

function NewCaseForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [id, setId] = useState("");
  const [title, setTitle] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [started, setStarted] = useState<Task | null>(null);
  const idHint = useId();
  const tracked = useTask(started?.id ?? null, {
    initial: started,
    onSettled: (task) => {
      if (task.state === "succeeded") onCreated();
    },
  });
  const task = tracked.task ?? started;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const caseId = id.trim();
    const caseTitle = title.trim();
    if (!CASE_ID.test(caseId)) {
      setError("Use 1 to 48 lowercase letters, digits or hyphens, starting with a letter or digit.");
      return;
    }
    if (!caseTitle) {
      setError("Give the case a title.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const reply = await api.createCase(caseId, caseTitle);
      setStarted(reply.task);
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSubmitting(false);
    }
  };

  if (task) {
    const href = caseHref(id.trim());
    return (
      <div className="stack" aria-live="polite">
        <p className="task-line">
          <TaskChip state={task.state} />
          <span>
            {task.state === "queued" && "Waiting for the task queue…"}
            {task.state === "running" && "Creating the case and its evidence volume…"}
            {task.state === "succeeded" && "Case created."}
            {task.state === "failed" && (task.error || "Case creation failed.")}
            {task.state === "cancelled" && "Case creation was cancelled."}
          </span>
        </p>
        {tracked.error && !isTerminal(task.state) && <p className="muted small">Status check failed: {tracked.error}</p>}
        <div className="form-actions">
          {task.state === "succeeded" && href && (
            <a className="button" href={href} onClick={onClose}>
              Open case
            </a>
          )}
          {(task.state === "failed" || task.state === "cancelled") && (
            <button type="button" onClick={() => setStarted(null)}>
              Try again
            </button>
          )}
          <button type="button" className="btn-secondary" onClick={onClose}>
            {isTerminal(task.state) ? "Close" : "Close and keep running"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <form className="stack" onSubmit={submit} noValidate>
      {error && (
        <p className="note note-err" role="alert">
          {error}
        </p>
      )}
      <label className="field">
        <span>Case ID</span>
        <input
          className="mono"
          name="id"
          value={id}
          onChange={(event) => setId(event.target.value.toLowerCase())}
          pattern={CASE_ID_PATTERN}
          maxLength={48}
          required
          autoFocus
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          aria-describedby={idHint}
        />
        <span className="hint" id={idHint}>
          Lowercase letters, digits and hyphens, up to 48 characters. It cannot change later.
        </span>
      </label>
      <label className="field">
        <span>Title</span>
        <input name="title" value={title} onChange={(event) => setTitle(event.target.value)} maxLength={TITLE_MAX} required autoComplete="off" />
      </label>
      <div className="form-actions">
        <button type="submit" disabled={submitting}>
          {submitting ? "Queuing…" : "Create case"}
        </button>
        <button type="button" className="btn-secondary" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}
