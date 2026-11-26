import { useMemo, useState, type FormEvent } from "react";
import { api, type Artifact, type Investigation, type Lead, type Observation, type Question, type Task } from "../../api";
import { EvidenceLink } from "../../components/EvidenceLink";
import { useToast } from "../../components/toast";
import { Badge, ConfirmButton, Empty, ErrorNote, Loading, Note, Panel, Time } from "../../components/ui";
import { DIGEST, isRecord, list, short, txt } from "../../format";
import { errorMessage, isTerminal, useResource, useTask } from "../../hooks";
import type { CaseContext } from "../CaseView";
import { LinksPanel } from "./LinksPanel";
import { RunPanel } from "./RunPanel";

const STATE_TONE: Record<string, "ok" | "warn" | "info" | "muted"> = {
  open: "info",
  proposed: "warn",
  answer_proposed: "warn",
  closed: "ok",
  withdrawn: "muted",
};

export function InvestigationTab({ ctx }: { ctx: CaseContext }) {
  const data = useResource((signal) => api.investigation(ctx.id, { signal }), `investigation:${ctx.id}`, () => 15000, [
    `investigation:${ctx.id}`,
  ]);
  const value = data.data;
  return (
    <div className="stack">
      {data.error && !value && <ErrorNote message={data.error} onRetry={data.reload} />}
      {!value && !data.error && <Loading label="Loading the investigation…" />}
      {value && (
        <>
          <RunPanel ctx={ctx} data={value} reload={data.reload} />
          <QuestionsPanel ctx={ctx} data={value} reload={data.reload} />
          <PlanPanel data={value} />
          <LeadsPanel ctx={ctx} data={value} reload={data.reload} />
          <LinksPanel ctx={ctx} data={value} reload={data.reload} />
        </>
      )}
    </div>
  );
}

function ModelMark({ row }: { row: { author?: string; audience?: string; grants?: string[] } }) {
  if (row.author !== "model") return null;
  const grants = list(row.grants).length;
  return (
    <Badge tone="muted" title="Written by a model. It is untrusted text.">
      model{row.audience ? `, ${txt(row.audience)}` : ""}
      {grants ? `, ${grants} grant${grants === 1 ? "" : "s"}` : ""}
    </Badge>
  );
}

function QuestionsPanel({ ctx, data, reload }: { ctx: CaseContext; data: Investigation; reload: () => void }) {
  const toast = useToast();
  const questions = list<Question>(data.questions).filter(isRecord);
  const [pending, setPending] = useState<Task | null>(null);
  const tracked = useTask(pending?.id ?? null, {
    initial: pending,
    onSettled: (task) => {
      if (task.state === "failed") toast(txt(task.error) || "Splitting the question failed.", "err");
      else toast("Proposed sub-questions are ready for your review.", "ok");
      reload();
    },
  });
  const splitting = tracked.task !== null && !isTerminal(tracked.task.state);
  const closed = ctx.detail.status === "Closed";

  const act = async (run: () => Promise<unknown>, message: string) => {
    try {
      await run();
      toast(message, "ok");
      reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };
  const split = async (question: Question) => {
    try {
      setPending((await api.splitQuestion(ctx.id, question.id)).task);
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <Panel title="Questions">
      <p className="muted small">
        Questions are the operator's goals for this case. Each names admitted artifacts and a checkable outcome. Only you close a question. A model
        can propose sub-questions, which count only after you accept them.
      </p>
      {questions.length === 0 && <Empty>No questions yet. Add one below.</Empty>}
      {questions.length > 0 && (
        <ul className="rows question-list">
          {questions.map((question) => (
            <li key={txt(question.id)} className="question">
              <div className="question-head">
                <code>{txt(question.id)}</code>
                <Badge tone={STATE_TONE[question.state] ?? "muted"}>{txt(question.state).replace("_", " ")}</Badge>
                {question.parent && <span className="muted small">from {txt(question.parent)}</span>}
                <ModelMark row={question} />
                <Time utc={question.created_utc} relative />
              </div>
              <p className="question-text">{txt(question.text)}</p>
              {question.outcome && (
                <p className="muted small">
                  <strong>Outcome:</strong> {txt(question.outcome)}
                </p>
              )}
              {list(question.artifacts).length > 0 && (
                <p className="small">
                  {list<string>(question.artifacts).map((digest) => (
                    <code key={digest} title={digest} className="spaced">
                      {short(digest, 12)}
                    </code>
                  ))}
                </p>
              )}
              {question.note && <p className="muted small">Note: {txt(question.note)}</p>}
              {!closed && (
                <div className="form-actions">
                  {question.state === "proposed" && (
                    <button type="button" className="btn-small" onClick={() => void act(() => api.setQuestionState(ctx.id, question.id, "open"), `${question.id} accepted.`)}>
                      Accept
                    </button>
                  )}
                  {(question.state === "open" || question.state === "answer_proposed") && (
                    <ConfirmButton
                      label="Close as answered"
                      prompt={`Close ${question.id}?`}
                      confirmLabel="Close"
                      confirmClassName="btn-small"
                      onConfirm={() => act(() => api.setQuestionState(ctx.id, question.id, "closed"), `${question.id} closed.`)}
                    />
                  )}
                  {question.state === "closed" && (
                    <button type="button" className="btn-secondary btn-small" onClick={() => void act(() => api.setQuestionState(ctx.id, question.id, "open"), `${question.id} reopened.`)}>
                      Reopen
                    </button>
                  )}
                  {question.state === "open" && (
                    <button type="button" className="btn-secondary btn-small" disabled={splitting} onClick={() => void split(question)}>
                      {splitting ? "Splitting…" : "Propose sub-questions"}
                    </button>
                  )}
                  {question.state !== "withdrawn" && question.state !== "closed" && (
                    <ConfirmButton
                      label={question.state === "proposed" ? "Reject" : "Withdraw"}
                      prompt={`Withdraw ${question.id}?`}
                      confirmLabel="Withdraw"
                      onConfirm={() => act(() => api.setQuestionState(ctx.id, question.id, "withdrawn"), `${question.id} withdrawn.`)}
                    />
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {!closed && <QuestionForm ctx={ctx} onAdded={reload} />}
    </Panel>
  );
}

function QuestionForm({ ctx, onAdded }: { ctx: CaseContext; onAdded: () => void }) {
  const toast = useToast();
  const artifacts = useMemo(
    () => list<Artifact>(ctx.detail.ledger?.artifacts).filter((item) => isRecord(item) && DIGEST.test(txt(item.sha256))),
    [ctx.detail.ledger],
  );
  const [text, setText] = useState("");
  const [outcome, setOutcome] = useState("");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!text.trim()) {
      setError("Write the question.");
      return;
    }
    setSaving(true);
    try {
      const question = await api.addQuestion(ctx.id, { text: text.trim(), outcome: outcome.trim(), artifacts: [...chosen] });
      toast(`${question.id} added.`, "ok");
      setText("");
      setOutcome("");
      setChosen(new Set());
      onAdded();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="stack-sm question-form" onSubmit={submit} noValidate>
      <p className="label">Add a question</p>
      {error && (
        <p className="note note-err" role="alert">
          {error}
        </p>
      )}
      <label className="field">
        <span>Question</span>
        <textarea rows={2} maxLength={500} value={text} onChange={(event) => setText(event.target.value)} placeholder="Does the config decoder at 0x… recover a C2 list?" />
      </label>
      <label className="field">
        <span>Checkable outcome</span>
        <input type="text" maxLength={300} value={outcome} onChange={(event) => setOutcome(event.target.value)} placeholder="What a tool result would have to show" />
      </label>
      <fieldset>
        <legend>Artifacts</legend>
        {artifacts.length === 0 ? (
          <p className="muted small">No artifacts are admitted yet. A question can name artifacts once they are.</p>
        ) : (
          <div className="check-grid">
            {artifacts.map((item) => (
              <label className="check" key={item.sha256}>
                <input
                  type="checkbox"
                  checked={chosen.has(item.sha256)}
                  onChange={(event) =>
                    setChosen((current) => {
                      const next = new Set(current);
                      if (event.target.checked) next.add(item.sha256);
                      else next.delete(item.sha256);
                      return next;
                    })
                  }
                />
                <code title={item.sha256}>{short(item.sha256, 16)}</code>
              </label>
            ))}
          </div>
        )}
      </fieldset>
      <div className="form-actions">
        <button type="submit" disabled={saving}>
          {saving ? "Adding…" : "Add question"}
        </button>
      </div>
    </form>
  );
}

function PlanPanel({ data }: { data: Investigation }) {
  const plan = data.plan;
  return (
    <Panel title="Plan">
      {!plan || list(plan.items).length === 0 ? (
        <Empty>No plan yet. A model writes one with update_plan.</Empty>
      ) : (
        <>
          <p className="muted small">
            <ModelMark row={plan} /> Updated <Time utc={plan.utc} relative />. Untrusted model text.
          </p>
          <ol className="plan">
            {list<string>(plan.items).map((item, index) => (
              <li key={index}>{txt(item)}</li>
            ))}
          </ol>
        </>
      )}
    </Panel>
  );
}

function LeadsPanel({ ctx, data, reload }: { ctx: CaseContext; data: Investigation; reload: () => void }) {
  const toast = useToast();
  const leads = list<Lead>(data.leads).filter(isRecord);
  const observations = list<Observation>(data.observations).filter(isRecord);
  const loose = observations.filter((row) => !row.lead);
  const closed = ctx.detail.status === "Closed";

  const setState = async (lead: Lead, state: "open" | "retired") => {
    try {
      await api.setLeadState(ctx.id, lead.id, state);
      toast(`${lead.id} ${state === "retired" ? "retired" : "reopened"}.`, "ok");
      reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <Panel title={`Leads and observations (${leads.length} leads, ${observations.length} observations)`}>
      <p className="muted small">
        Models add leads and observations through the broker. An observed observation must cite evidence: an exact tool result from this case.
        These are notes, not findings.
      </p>
      {leads.length === 0 && loose.length === 0 && <Empty>No leads or observations yet.</Empty>}
      <ul className="rows lead-list">
        {leads.map((lead) => (
          <li key={txt(lead.id)} className="lead">
            <div className="question-head">
              <code>{txt(lead.id)}</code>
              <Badge tone={lead.state === "open" ? "info" : "muted"}>{txt(lead.state)}</Badge>
              <code title={txt(lead.artifact)}>{short(lead.artifact, 12)}</code>
              {lead.address && <code>{txt(lead.address)}</code>}
              {lead.offset !== null && lead.offset !== undefined && <code>offset {txt(lead.offset)}</code>}
              {lead.question && <span className="muted small">for {txt(lead.question)}</span>}
              <ModelMark row={lead} />
              {!closed && lead.state === "open" && (
                <button type="button" className="btn-secondary btn-small" onClick={() => void setState(lead, "retired")}>
                  Retire
                </button>
              )}
              {!closed && lead.state === "retired" && (
                <button type="button" className="btn-secondary btn-small" onClick={() => void setState(lead, "open")}>
                  Reopen
                </button>
              )}
            </div>
            <p className="question-text">{txt(lead.title)}</p>
            {lead.summary && (
              <p className="small">
                <span className="muted">Wrap-up (untrusted model text): </span>
                {txt(lead.summary.text)}
              </p>
            )}
            <ObservationList caseId={ctx.id} rows={observations.filter((row) => row.lead === lead.id)} />
          </li>
        ))}
      </ul>
      {loose.length > 0 && (
        <>
          <p className="label">Observations without a lead</p>
          <ObservationList caseId={ctx.id} rows={loose} />
        </>
      )}
      {observations.some((row) => row.kind === "observed" && list(row.evidence).length === 0) && (
        <Note tone="warn">An observed observation without evidence should not exist. Check the audit.</Note>
      )}
    </Panel>
  );
}

function ObservationList({ caseId, rows }: { caseId: string; rows: Observation[] }) {
  if (rows.length === 0) return null;
  return (
    <ul className="plain observations">
      {rows.slice(-50).map((row) => (
        <li key={txt(row.id)}>
          <code>{txt(row.id)}</code> <Badge tone={row.kind === "observed" ? "ok" : "muted"}>{txt(row.kind)}</Badge> {txt(row.text)}{" "}
          {list<string>(row.evidence).map((id) => (
            <EvidenceLink key={id} caseId={caseId} id={id} />
          ))}
        </li>
      ))}
    </ul>
  );
}
