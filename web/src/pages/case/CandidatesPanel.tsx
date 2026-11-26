import { useState, type FormEvent } from "react";
import { api, type Candidate, type Task } from "../../api";
import { EvidenceLink } from "../../components/EvidenceLink";
import { useToast } from "../../components/toast";
import { Badge, ConfirmButton, Dialog, Empty, ErrorNote, Loading, Panel, Time } from "../../components/ui";
import { isRecord, list, short, txt } from "../../format";
import { errorMessage, isTerminal, useResource, useTask } from "../../hooks";
import type { CaseContext } from "../CaseView";

const KINDS = ["observed", "inferred", "corroborated", "unknown"];
const CONFIDENCE = ["low", "medium", "high"];
const CHECK_LABEL: Record<string, string> = { passed: "References resolve", failed: "References missing", not_assessed: "Not assessed" };

/** Findings that models proposed. A check and a review run advise; only the operator records or rejects one. */
export function CandidatesPanel({ ctx }: { ctx: CaseContext }) {
  const data = useResource((signal) => api.investigation(ctx.id, { signal }), `investigation:${ctx.id}`, () => 15000, [
    `investigation:${ctx.id}`,
  ]);
  const candidates = list<Candidate>(data.data?.candidates).filter(isRecord);
  const open = candidates.filter((row) => row.state === "proposed");
  const decided = candidates.filter((row) => row.state !== "proposed").slice(-10).reverse();
  const reload = () => {
    data.reload();
    ctx.reload();
  };
  return (
    <Panel title={open.length ? `Proposed findings waiting on you (${open.length})` : "Proposed findings"}>
      <p className="muted small">
        A model proposes a finding with propose_finding. The Forge checks that its references resolve: cited evidence exists in this case, cited
        artifacts are admitted and every address in the claim appears in the cited evidence. A review run argues alternatives. Neither one records
        anything. You record the finding, editing it first if needed, or reject it.
      </p>
      {data.error && !data.data && <ErrorNote message={data.error} onRetry={data.reload} />}
      {!data.data && !data.error && <Loading label="Loading proposed findings…" />}
      {data.data && open.length === 0 && <Empty>No proposed findings are waiting.</Empty>}
      <ul className="rows candidate-list">
        {open.map((row) => (
          <li key={txt(row.id)}>
            <CandidateCard ctx={ctx} candidate={row} reload={reload} />
          </li>
        ))}
      </ul>
      {decided.length > 0 && (
        <>
          <p className="label">Recently decided</p>
          <ul className="rows">
            {decided.map((row) => (
              <li key={txt(row.id)} className="request-decided">
                <code>{txt(row.id)}</code>
                <Badge tone={row.state === "recorded" ? "ok" : "muted"}>{txt(row.state)}</Badge>
                {row.finding && <code>{txt(row.finding)}</code>}
                <span className="muted small">
                  by {txt(row.decided_by)} <Time utc={row.decided_utc} relative />
                  {row.note && ` · ${txt(row.note)}`}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}

function CandidateCard({ ctx, candidate, reload }: { ctx: CaseContext; candidate: Candidate; reload: () => void }) {
  const toast = useToast();
  const [pending, setPending] = useState<Task | null>(null);
  const [recording, setRecording] = useState(false);
  const tracked = useTask(pending?.id ?? null, {
    initial: pending,
    onSettled: (task) => {
      toast(task.state === "failed" ? txt(task.error) || "The task failed." : `${candidate.id}: ${task.kind === "review" ? "review finished" : "recorded"}.`, task.state === "failed" ? "err" : "ok");
      reload();
    },
  });
  const busy = tracked.task !== null && !isTerminal(tracked.task.state);
  const disabled = ctx.inactive !== null || busy;
  const check = candidate.check;
  const verdict = list<Candidate["verdicts"][number]>(candidate.verdicts).slice(-1)[0];

  const start = async (run: () => Promise<{ task: Task }>) => {
    try {
      setPending((await run()).task);
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };
  const recheck = async () => {
    try {
      await api.checkCandidate(ctx.id, candidate.id);
      reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };
  const reject = async () => {
    try {
      await api.rejectCandidate(ctx.id, candidate.id);
      toast(`${candidate.id} rejected.`, "ok");
      reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <div className="candidate">
      <div className="question-head">
        <code>{txt(candidate.id)}</code>
        <Badge>{txt(candidate.kind)}</Badge>
        <Badge>{txt(candidate.confidence)} confidence</Badge>
        {check && (
          <Badge tone={check.result === "passed" ? "ok" : check.result === "failed" ? "err" : "warn"} title="Deterministic reference check, not verification">
            {CHECK_LABEL[check.result] ?? txt(check.result)}
          </Badge>
        )}
        {verdict && <Badge tone={verdict.verdict === "supported" ? "ok" : "warn"}>review: {txt(verdict.verdict)}</Badge>}
        <Badge tone="muted" title="Written by a model. Untrusted text.">
          model, {txt(candidate.audience)}
        </Badge>
        <Time utc={candidate.utc} relative />
      </div>
      <p className="question-text">{txt(candidate.claim)}</p>
      {candidate.limitations && <p className="small"><strong>Limitations:</strong> {txt(candidate.limitations)}</p>}
      {candidate.counterevidence && <p className="small"><strong>Counterevidence:</strong> {txt(candidate.counterevidence)}</p>}
      <p className="small">
        <strong>Artifacts:</strong>{" "}
        {list<string>(candidate.artifacts).map((digest) => (
          <code key={digest} title={digest} className="spaced">
            {short(digest, 12)}
          </code>
        ))}{" "}
        <strong>Evidence:</strong>{" "}
        {list<string>(candidate.evidence).length === 0 ? <span className="muted">none cited</span> : list<string>(candidate.evidence).map((id) => <EvidenceLink key={id} caseId={ctx.id} id={id} />)}
      </p>
      {check && list(check.problems).length > 0 && (
        <ul className="plain small check-problems">
          {list<{ code: string; ref: string | null }>(check.problems).map((problem, index) => (
            <li key={index}>
              {txt(problem.code).replace(/_/g, " ")}
              {problem.ref && (
                <>
                  {" "}
                  <code>{short(problem.ref, 16)}</code>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {verdict && (
        <p className="small">
          <strong>Review rationale</strong> <span className="muted">({txt(verdict.model)}, untrusted)</span>: {txt(verdict.rationale)}
        </p>
      )}
      <div className="form-actions">
        <button type="button" className="btn-small" disabled={disabled} onClick={() => setRecording(true)}>
          Record as finding…
        </button>
        <button type="button" className="btn-secondary btn-small" disabled={disabled} onClick={() => void start(() => api.reviewCandidate(ctx.id, candidate.id))}>
          {busy && tracked.task?.kind === "review" ? "Reviewing…" : "Run a review"}
        </button>
        <button type="button" className="btn-secondary btn-small" disabled={busy} onClick={() => void recheck()}>
          Re-check references
        </button>
        <ConfirmButton label="Reject" prompt={`Reject ${candidate.id}?`} confirmLabel="Reject" disabled={disabled} onConfirm={reject} />
      </div>
      <Dialog open={recording} title={`Record ${candidate.id} as a finding`} onClose={() => setRecording(false)}>
        <RecordForm
          candidate={candidate}
          onSubmit={async (input) => {
            await start(() => api.recordCandidate(ctx.id, candidate.id, input));
            setRecording(false);
          }}
        />
      </Dialog>
    </div>
  );
}

function RecordForm({ candidate, onSubmit }: { candidate: Candidate; onSubmit: (input: { claim: string; kind: string; confidence: string }) => Promise<void> }) {
  const [claim, setClaim] = useState(txt(candidate.claim));
  const [kind, setKind] = useState(txt(candidate.kind));
  const [confidence, setConfidence] = useState(txt(candidate.confidence));
  const [saving, setSaving] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit({ claim: claim.trim(), kind, confidence });
    } finally {
      setSaving(false);
    }
  };
  return (
    <form className="stack-sm" onSubmit={submit}>
      <p className="muted small">
        This writes the case ledger through the operator finding path. The claim was written by a model: read it and edit it before you record it.
        Its evidence is cited as <code>evidence:&lt;id&gt;</code>.
      </p>
      <label className="field">
        <span>Claim</span>
        <textarea rows={6} maxLength={2000} value={claim} onChange={(event) => setClaim(event.target.value)} required />
      </label>
      <div className="form-grid">
        <label className="field">
          <span>Kind</span>
          <select value={kind} onChange={(event) => setKind(event.target.value)}>
            {KINDS.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Confidence</span>
          <select value={confidence} onChange={(event) => setConfidence(event.target.value)}>
            {CONFIDENCE.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="form-actions">
        <button type="submit" disabled={saving || !claim.trim()}>
          {saving ? "Recording…" : "Record finding"}
        </button>
      </div>
    </form>
  );
}
