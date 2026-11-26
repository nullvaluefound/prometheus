import { useState, type FormEvent } from "react";
import { api, type Task } from "../api";
import { isRecord, txt } from "../format";
import { errorMessage, isTerminal, useTask } from "../hooks";

/** Ask about the chat or the investigation without changing it: a snapshot, no tools, nothing saved. */
export function SideQuestion({ caseId, source, disabled }: { caseId: string; source: "chat" | "investigation"; disabled?: boolean }) {
  const [question, setQuestion] = useState("");
  const [pending, setPending] = useState<Task | null>(null);
  const [error, setError] = useState<string | null>(null);
  const tracked = useTask(pending?.id ?? null, { initial: pending });
  const task = tracked.task ?? pending;
  const busy = task !== null && !isTerminal(task.state);
  const answer = task?.state === "succeeded" && isRecord(task.result) ? txt(task.result.answer) : null;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!question.trim()) return;
    setError(null);
    try {
      setPending((await api.ask(caseId, question.trim(), source)).task);
    } catch (failure) {
      setError(errorMessage(failure));
    }
  };

  return (
    <details className="side-question">
      <summary className="small">Ask about this {source === "chat" ? "conversation" : "investigation"}</summary>
      <form className="composer-inline" onSubmit={submit}>
        <label className="field">
          <span>Side question</span>
          <input type="text" maxLength={2000} value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Why did it stop? What is still open?" disabled={disabled} />
        </label>
        <button type="submit" className="btn-secondary btn-small" disabled={disabled || busy || !question.trim()}>
          {busy ? "Asking…" : "Ask"}
        </button>
      </form>
      <p className="muted small">The model answers from a snapshot, with no tools. Nothing is added to the {source === "chat" ? "conversation" : "investigation"}.</p>
      {error && <p className="note note-err">{error}</p>}
      {task?.state === "failed" && <p className="note note-err">{txt(task.error) || "The side question failed."}</p>}
      {answer !== null && (
        <p className="msg-text">
          <span className="muted small">Answer (untrusted model text): </span>
          {answer}
        </p>
      )}
    </details>
  );
}
