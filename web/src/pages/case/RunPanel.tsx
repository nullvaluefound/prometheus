import { useState, type FormEvent } from "react";
import { api, type Investigation, type InvestigationRun } from "../../api";
import { useToast } from "../../components/toast";
import { SideQuestion } from "../../components/SideQuestion";
import { Badge, ConfirmButton, Note, Panel, Time } from "../../components/ui";
import { fmtCount, list, short, txt } from "../../format";
import { errorMessage } from "../../hooks";
import type { CaseContext } from "../CaseView";

const TONE: Record<string, "ok" | "warn" | "info" | "muted" | "err"> = {
  queued: "info",
  running: "info",
  paused: "warn",
  waiting: "warn",
  settling: "info",
  answered: "ok",
  exhausted: "warn",
  failed: "err",
  cancelled: "muted",
};
const TERMINAL = ["answered", "exhausted", "failed", "cancelled"];

function seconds(total: number): string {
  const value = Math.max(0, Math.round(total));
  if (value < 60) return `${value}s`;
  const minutes = Math.floor(value / 60);
  return minutes < 60 ? `${minutes}m ${value % 60}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

/** The case's investigation run: a planner and lead workers pursuing the open questions, under budgets. */
export function RunPanel({ ctx, data, reload }: { ctx: CaseContext; data: Investigation; reload: () => void }) {
  const toast = useToast();
  const run = data.run ?? null;
  const live = run !== null && !TERMINAL.includes(run.state);
  const closed = ctx.detail.status === "Closed";
  const act = async (action: "pause" | "resume" | "cancel" | "acknowledge", done: string) => {
    try {
      await api.investigationAction(ctx.id, action);
      toast(done, "ok");
      reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <Panel title="Investigation run">
      <p className="muted small">
        A run pursues the open questions in short steps: a planner adds and retires leads, lead workers analyze them through the broker, and new
        proposals get a review. It never closes a question or records a finding. It waits on you when it has nothing left to do, and settles with a
        summary when a budget runs out.
      </p>
      {run && <RunState run={run} />}
      {!closed && run && live && (
        <div className="form-actions">
          {["queued", "running", "settling"].includes(run.state) && (
            <button type="button" className="btn-secondary btn-small" onClick={() => void act("pause", "Investigation paused.")}>
              Pause
            </button>
          )}
          {["paused", "waiting"].includes(run.state) && (
            <button type="button" className="btn-small" onClick={() => void act("resume", "Investigation resumed.")}>
              Resume
            </button>
          )}
          <ConfirmButton label="Cancel run" prompt="Cancel this investigation?" confirmLabel="Cancel run" onConfirm={() => act("cancel", "Investigation cancelled.")} />
        </div>
      )}
      {!closed && run && live && <MessageForm ctx={ctx} onSent={reload} />}
      {run && TERMINAL.includes(run.state) && !run.acknowledged && ["exhausted", "failed"].includes(run.state) && (
        <div className="form-actions">
          <button type="button" className="btn-secondary btn-small" onClick={() => void act("acknowledge", "Marked as seen.")}>
            Mark as seen
          </button>
        </div>
      )}
      {!closed && (!run || TERMINAL.includes(run.state)) && <StartForm ctx={ctx} onStarted={reload} again={run !== null} />}
      {run && <SideQuestion caseId={ctx.id} source="investigation" disabled={!ctx.detail.settings?.model} />}
    </Panel>
  );
}

function RunState({ run }: { run: InvestigationRun }) {
  const active = run.spent.active_seconds + (run.active_since ? Math.max(0, Date.now() / 1000 - run.active_since) : 0);
  return (
    <div className="stack-sm">
      <div className="question-head">
        <code>{txt(run.id)}</code>
        <Badge tone={TONE[run.state] ?? "muted"}>{txt(run.state)}</Badge>
        <span className="muted small">
          {list<string>(run.questions).join(", ")} · lead role {txt(run.lead_role)} · started by {txt(run.started_by)}{" "}
          <Time utc={run.created_utc} relative />
        </span>
      </div>
      <dl className="kv">
        <div>
          <dt>Broker calls</dt>
          <dd>
            {fmtCount(run.spent.calls)} of {fmtCount(run.budgets.calls)}
          </dd>
        </div>
        <div>
          <dt>Model tokens</dt>
          <dd>
            {fmtCount(run.spent.tokens)} of {fmtCount(run.budgets.tokens)}
          </dd>
        </div>
        <div>
          <dt>Active time</dt>
          <dd>
            {seconds(active)} of {run.budgets.minutes} min <span className="muted small">· stops counting while paused or waiting</span>
          </dd>
        </div>
        <div>
          <dt>Steps</dt>
          <dd>{fmtCount(run.steps)}</dd>
        </div>
      </dl>
      {run.state === "waiting" && run.need && (
        <Note tone="warn">
          <strong>Waiting on you.</strong> {run.need.author === "model" ? "The planner says (untrusted model text): " : ""}
          {txt(run.need.text)}
          {list(run.need.flags).length > 0 && (
            <span className="block small">Names values the case never showed: {list<string>(run.need.flags).map((value) => short(value, 16)).join(", ")}.</span>
          )}
        </Note>
      )}
      {run.error && <Note tone="err">{txt(run.error)}</Note>}
      {run.summary && (
        <div>
          <p className="label">Settle summary (untrusted model text)</p>
          <p className="question-text">{txt(run.summary.text)}</p>
        </div>
      )}
      {run.message && <p className="muted small">Message for the next lead: {txt(run.message.text)}</p>}
      <details>
        <summary className="small">History</summary>
        <ol className="plain small">
          {list<InvestigationRun["history"][number]>(run.history).map((row, index) => (
            <li key={index}>
              {txt(row.from) || "new"} → {txt(row.to)} by {txt(row.by)} <Time utc={row.utc} relative />
            </li>
          ))}
        </ol>
      </details>
    </div>
  );
}

function StartForm({ ctx, onStarted, again }: { ctx: CaseContext; onStarted: () => void; again: boolean }) {
  const toast = useToast();
  const [role, setRole] = useState<"evidence" | "native">("evidence");
  const [calls, setCalls] = useState("160");
  const [tokens, setTokens] = useState("600000");
  const [minutes, setMinutes] = useState("60");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      await api.startInvestigation(ctx.id, { lead_role: role, budgets: { calls: Number(calls), tokens: Number(tokens), minutes: Number(minutes) } });
      toast("Investigation started.", "ok");
      onStarted();
    } catch (error) {
      toast(errorMessage(error), "err");
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="stack-sm question-form" onSubmit={submit}>
      <p className="label">{again ? "Start a new run" : "Start a run"}</p>
      <div className="form-grid">
        <label className="field">
          <span>Lead role</span>
          <select value={role} onChange={(event) => setRole(event.target.value as "evidence" | "native")}>
            <option value="evidence">evidence</option>
            <option value="native">native</option>
          </select>
        </label>
        <label className="field">
          <span>Broker calls</span>
          <input type="number" min={8} max={2000} value={calls} onChange={(event) => setCalls(event.target.value)} />
        </label>
        <label className="field">
          <span>Model tokens</span>
          <input type="number" min={10000} max={20000000} step={10000} value={tokens} onChange={(event) => setTokens(event.target.value)} />
        </label>
        <label className="field">
          <span>Active minutes</span>
          <input type="number" min={5} max={1440} value={minutes} onChange={(event) => setMinutes(event.target.value)} />
        </label>
      </div>
      <p className="muted small">
        A run uses the case's chat model and needs an open question naming an admitted artifact and a checkable outcome. Excerpts still need your grants.
      </p>
      <div className="form-actions">
        <button type="submit" disabled={busy || ctx.inactive !== null}>
          {busy ? "Starting…" : "Start investigation"}
        </button>
      </div>
    </form>
  );
}

function MessageForm({ ctx, onSent }: { ctx: CaseContext; onSent: () => void }) {
  const toast = useToast();
  const [text, setText] = useState("");
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!text.trim()) return;
    try {
      await api.investigationAction(ctx.id, "message", text.trim());
      setText("");
      toast("The next lead will get your message.", "ok");
      onSent();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };
  return (
    <form className="composer-inline" onSubmit={submit}>
      <label className="field">
        <span>Message to the next lead</span>
        <input type="text" maxLength={1000} value={text} onChange={(event) => setText(event.target.value)} placeholder="For example: check the decoder at 0x…" />
      </label>
      <button type="submit" className="btn-secondary btn-small" disabled={!text.trim()}>
        Send
      </button>
    </form>
  );
}
