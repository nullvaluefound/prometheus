import { useState } from "react";
import { api, type Task } from "../../api";
import { TaskOutcome } from "../../components/ResultView";
import { useToast } from "../../components/toast";
import { ConfirmButton, Note, Panel, TaskChip, Time } from "../../components/ui";
import { fmtCount, list, plural, txt } from "../../format";
import { errorMessage, isTerminal, useTask } from "../../hooks";
import { caseHref } from "../../router";
import type { CaseContext } from "../CaseView";

export function OverviewTab({
  ctx,
  reportTask,
  onReport,
}: {
  ctx: CaseContext;
  reportTask: Task | null;
  onReport: (task: Task) => void;
}) {
  const { id, detail } = ctx;
  const toast = useToast();
  const [acting, setActing] = useState(false);
  const tracked = useTask(reportTask?.id ?? null, { initial: reportTask });
  const report = tracked.task ?? reportTask;
  const reportBusy = report !== null && !isTerminal(report.state);
  const ledger = detail.ledger;
  const rules = detail.yara_rules;
  const settings = detail.settings;

  const control = async (action: "pause" | "resume") => {
    setActing(true);
    try {
      const reply = action === "pause" ? await api.pauseCase(id) : await api.resumeCase(id);
      toast(`Case ${txt(reply.status).toLowerCase() || (action === "pause" ? "paused" : "resumed")}.`, "ok");
      ctx.reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    } finally {
      setActing(false);
    }
  };

  const generate = async () => {
    try {
      const reply = await api.report(id);
      onReport(reply.task);
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <div className="stack">
      <div className="columns">
        <Panel title="Scope">
          <dl className="kv">
            <div>
              <dt>Status</dt>
              <dd>{txt(detail.status)}</dd>
            </div>
            <div>
              <dt>Image</dt>
              <dd>
                <code>{txt(detail.image)}</code>
              </dd>
            </div>
            <div>
              <dt>Engine</dt>
              <dd>
                <code>{txt(detail.engine)}</code>
              </dd>
            </div>
            <div>
              <dt>YARA rules</dt>
              <dd>
                {rules ? (
                  <>
                    <code>{txt(rules.sha256)}</code>
                    <span className="muted small"> · {plural(typeof rules.rules === "number" ? rules.rules : 0, "rule")}</span>
                  </>
                ) : (
                  <span className="muted">None imported</span>
                )}
              </dd>
            </div>
            <div>
              <dt>Chat model</dt>
              <dd>
                {settings?.model ? <code>{txt(settings.model)}</code> : <span className="muted">None selected</span>}
                <span className="muted small"> · role {txt(settings?.role)}</span>
                {settings?.allow_cloud && <span className="chip chip-warn chip-nodot">Cloud allowed</span>}
              </dd>
            </div>
          </dl>
          <div className="control">
            {detail.status === "Ready" && (
              <>
                <button type="button" className="btn-danger" onClick={() => control("pause")} disabled={acting}>
                  {acting ? "Pausing…" : "Pause case"}
                </button>
                <p className="muted small">Pausing closes new broker actions at once, including chat and tool runs.</p>
              </>
            )}
            {detail.status === "Paused" && (
              <>
                <ConfirmButton
                  label="Resume case"
                  prompt="Resume broker actions for this case?"
                  confirmLabel="Resume"
                  className="btn-small"
                  confirmClassName="btn-small"
                  disabled={acting}
                  onConfirm={() => control("resume")}
                />
                <p className="muted small">Review the scope, grants and model settings before resuming.</p>
              </>
            )}
            {detail.status === "Closed" && (
              <p className="muted small">Closure is irreversible. The ledger, report and evidence volume are retained read-only.</p>
            )}
            {detail.status === "Pending" && <p className="muted small">The case is still being created. This page refreshes on its own.</p>}
          </div>
        </Panel>

        <Panel title="Ledger">
          {ledger ? (
            <>
              <p className="ledger-title">{txt(ledger.title) || <span className="muted">Untitled ledger</span>}</p>
              <ul className="rows">
                <li>
                  <a href={caseHref(id, "artifacts") ?? "#/cases"}>Artifacts</a>
                  <span>{fmtCount(list(ledger.artifacts).length)}</span>
                </li>
                <li>
                  <a href={caseHref(id, "findings") ?? "#/cases"}>Findings</a>
                  <span>{fmtCount(list(ledger.findings).length)}</span>
                </li>
                <li>
                  <a href={caseHref(id, "rules") ?? "#/cases"}>Active grants</a>
                  <span>{fmtCount(list(detail.grants).length)}</span>
                </li>
              </ul>
            </>
          ) : (
            <Note tone="warn">The evidence ledger is unavailable. Check the Docker engine and run verify.</Note>
          )}
        </Panel>
      </div>

      <Panel
        title="Report"
        actions={
          <button type="button" onClick={generate} disabled={reportBusy || detail.status === "Pending"}>
            {reportBusy ? "Generating…" : report ? "Generate again" : "Generate report"}
          </button>
        }
      >
        {report ? (
          <div className="stack-sm">
            <p className="task-line">
              <TaskChip state={report.state} />
              <span>{txt(report.title) || "Report"}</span>
              <Time utc={report.finished_utc ?? report.created_utc} relative />
            </p>
            {tracked.error && !isTerminal(report.state) && <p className="muted small">Status check failed: {tracked.error}</p>}
            <TaskOutcome task={report} />
          </div>
        ) : (
          <p className="muted">Build a Markdown report from the ledger. It runs as a queued task and appears here as plain text.</p>
        )}
      </Panel>
    </div>
  );
}
