import { useState } from "react";
import { api, type CaseStatus, type Overview, type Task, type WaitingItem } from "../api";
import { NewCaseDialog } from "../components/NewCaseDialog";
import { AuditTable } from "../components/AuditTable";
import { CaseLink, Empty, ErrorNote, Loading, Panel, RefreshButton, StatusChip, TaskChip, Time } from "../components/ui";
import { fmtCount, list, plural, short, txt } from "../format";
import { errorMessage, useDocumentTitle, useResource } from "../hooks";
import { useToast } from "../components/toast";
import { caseHref } from "../router";

const STATUSES: CaseStatus[] = ["Ready", "Paused", "Pending", "Closed"];

function busy(overview: Overview): boolean {
  return Boolean(overview.tasks?.running) || (overview.tasks?.queued ?? 0) > 0;
}

export function Dashboard() {
  useDocumentTitle("Dashboard");
  const overview = useResource((signal) => api.overview({ signal }), "overview", (data) => (busy(data) ? 2000 : 15000), [
    "tasks",
    "waiting",
    "case:*",
  ]);
  const [creating, setCreating] = useState(false);
  const data = overview.data;

  return (
    <>
      <div className="page-head">
        <h1>Forge</h1>
        <div className="page-actions">
          <RefreshButton onClick={overview.reload} busy={overview.loading && Boolean(data)} />
          <button type="button" onClick={() => setCreating(true)}>
            New case
          </button>
        </div>
      </div>
      <NewCaseDialog open={creating} onClose={() => setCreating(false)} onCreated={overview.reload} />
      {overview.error && <ErrorNote message={overview.error} onRetry={overview.reload} />}
      {!data && !overview.error && <Loading label="Loading the overview…" />}
      {data && <DashboardBody data={data} onNewCase={() => setCreating(true)} onChange={overview.reload} />}
    </>
  );
}

function DashboardBody({ data, onNewCase, onChange }: { data: Overview; onNewCase: () => void; onChange: () => void }) {
  const cases = list<Overview["cases"][number]>(data.cases);
  const apprentices = list<Overview["apprentices"][number]>(data.apprentices);
  const recent = list<Task>(data.tasks?.recent);
  const running = data.tasks?.running ?? null;
  const queued = data.tasks?.queued ?? 0;
  const verified = apprentices.filter((item) => item.verified).length;
  const counts = STATUSES.map((status) => [status, cases.filter((item) => item.status === status).length] as const);

  return (
    <div className="stack">
      <div className="stats">
        <section className="stat" aria-label="Cases">
          <p className="stat-label">Cases</p>
          <p className="stat-value">{fmtCount(cases.length)}</p>
          <p className="stat-detail">
            {counts
              .filter(([, count]) => count > 0)
              .map(([status, count]) => (
                <span key={status} className="stat-pair">
                  <StatusChip status={status} /> {count}
                </span>
              ))}
            {cases.length === 0 && <span className="muted">None yet</span>}
          </p>
        </section>
        <section className="stat" aria-label="Apprentices">
          <p className="stat-label">Apprentices</p>
          <p className="stat-value">
            {verified}
            <span className="stat-of">/{apprentices.length}</span>
          </p>
          <p className="stat-detail muted">{verified === apprentices.length && apprentices.length > 0 ? "All verified" : "Verified by selftest"}</p>
        </section>
        <section className="stat" aria-label="Task queue">
          <p className="stat-label">Task queue</p>
          <p className="stat-value">{running ? 1 + queued : queued}</p>
          <p className="stat-detail muted">{running ? `1 running, ${queued} queued` : queued ? `${queued} queued` : "Idle"}</p>
        </section>
        <section className="stat" aria-label="Models">
          <p className="stat-label">Models</p>
          <p className="stat-value">{fmtCount(data.models)}</p>
          <p className="stat-detail">
            <a href="#/models">{data.models ? "Manage models" : "Add a model"}</a>
          </p>
        </section>
      </div>

      <WaitingPanel items={list<WaitingItem>(data.waiting?.items)} count={data.waiting?.count ?? 0} onChange={onChange} />

      <Panel title="Cases" actions={<a href="#/cases">All cases</a>}>
        {cases.length === 0 ? (
          <div className="empty-block">
            <Empty>No cases yet. Create one to admit artifacts and start static analysis.</Empty>
            <button type="button" onClick={onNewCase}>
              New case
            </button>
          </div>
        ) : (
          <ul className="card-grid">
            {cases.map((item) => {
              const href = caseHref(item.id);
              const body = (
                <>
                  <span className="case-card-top">
                    <code>{txt(item.id)}</code>
                    <StatusChip status={item.status} />
                  </span>
                  <span className="case-card-title">{txt(item.title) || <span className="muted">Untitled</span>}</span>
                  <span className="case-card-meta">
                    <span>{item.artifacts === null ? "Ledger not read" : plural(item.artifacts, "artifact")}</span>
                    {item.findings !== null && <span>{plural(item.findings, "finding")}</span>}
                    {item.updated_utc && <Time utc={item.updated_utc} relative />}
                  </span>
                </>
              );
              return <li key={txt(item.id)}>{href ? <a className="case-card" href={href}>{body}</a> : <div className="case-card">{body}</div>}</li>;
            })}
          </ul>
        )}
      </Panel>

      <div className="columns">
        <Panel title="Task queue" actions={<a href="#/tasks">All tasks</a>}>
          <div className="running">
            <p className="label">Running</p>
            {running ? <TaskLine task={running} /> : <p className="muted">Nothing is running.</p>}
            <p className="muted small">{queued ? `${plural(queued, "task")} waiting. Tasks run one at a time, in order.` : "No tasks waiting."}</p>
          </div>
          <p className="label">Recent</p>
          {recent.length === 0 ? (
            <Empty>No tasks yet.</Empty>
          ) : (
            <ul className="rows">
              {recent.map((task) => (
                <li key={txt(task.id)}>
                  <TaskLine task={task} />
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Apprentices">
          {apprentices.length === 0 ? (
            <Empty>No Apprentices reported.</Empty>
          ) : (
            <ul className="rows">
              {apprentices.map((item) => (
                <li key={txt(item.name)}>
                  <span>{txt(item.name)}</span>
                  {item.verified ? <span className="chip chip-ok">Verified</span> : <span className="chip chip-warn">Awaiting baseline</span>}
                </li>
              ))}
            </ul>
          )}
          <p className="muted small">Apprentices are the isolated static workers. The selftest records which ones match the pinned baseline.</p>
        </Panel>
      </div>

      <Panel title="Latest audit decisions">
        <AuditTable events={list(data.audit)} showCase empty="No audit events yet." />
      </Panel>
    </div>
  );
}

export function TaskLine({ task }: { task: Task }) {
  const href = caseHref(task.case);
  return (
    <span className="task-line">
      <TaskChip state={task.state} />
      <span className="task-line-title">{txt(task.title) || txt(task.kind)}</span>
      {task.case && <CaseLink id={task.case} href={href} />}
      <Time utc={task.finished_utc ?? task.started_utc ?? task.created_utc} relative />
    </span>
  );
}

function WaitingLine({ item, onChange }: { item: WaitingItem; onChange: () => void }) {
  const toast = useToast();
  if (item.kind === "task_failed") {
    const dismiss = async () => {
      try {
        await api.dismissTask(item.id);
        onChange();
      } catch (error) {
        toast(errorMessage(error), "err");
      }
    };
    return (
      <>
        <span className="chip chip-err">Task failed</span>
        {item.case && <CaseLink id={item.case} href={caseHref(item.case)} />}
        <span>{txt(item.title)}</span>
        <span className="muted small">{txt(item.error)}</span>
        <Time utc={item.utc} relative />
        <button type="button" className="btn-secondary btn-small" onClick={() => void dismiss()}>
          Dismiss
        </button>
      </>
    );
  }
  if (item.kind === "grant_request") {
    return (
      <>
        <span className="chip chip-warn">Grant request</span>
        <CaseLink id={item.case} href={caseHref(item.case, "rules")} />
        <code>{txt(item.tool)}</code>
        <code title={txt(item.artifact)}>{short(item.artifact, 12)}</code>
        <span className="muted small">for {item.audience === "mcp" ? "a cloud or MCP model" : "the local model"}</span>
        {item.flagged && <span className="chip chip-warn">reason names unverified values</span>}
        <Time utc={item.utc} relative />
      </>
    );
  }
  if (item.kind.startsWith("investigation_")) {
    const label = item.kind === "investigation_waiting" ? "Investigation waiting" : item.kind === "investigation_failed" ? "Investigation failed" : "Investigation exhausted";
    return (
      <>
        <span className={`chip ${item.kind === "investigation_failed" ? "chip-err" : "chip-warn"}`}>{label}</span>
        <CaseLink id={item.case} href={caseHref(item.case, "investigation")} />
        <code>{txt(item.id)}</code>
        {item.need && <span className="muted small">planner: {txt(item.need)}</span>}
        {item.flagged && <span className="chip chip-warn">need names unverified values</span>}
        {item.error && <span className="muted small">{txt(item.error)}</span>}
        <Time utc={item.utc} relative />
      </>
    );
  }
  if (item.kind === "candidate") {
    return (
      <>
        <span className="chip chip-info">Proposed finding</span>
        <CaseLink id={item.case} href={caseHref(item.case, "findings")} />
        <code>{txt(item.id)}</code>
        {item.check && <span className="muted small">check {txt(item.check).replace("_", " ")}</span>}
        {item.verdict && <span className="muted small">review {txt(item.verdict)}</span>}
        <Time utc={item.utc} relative />
      </>
    );
  }
  return (
    <>
      <span className="chip chip-info">{item.kind === "question_proposed" ? "Proposed sub-question" : "Answer proposed"}</span>
      <CaseLink id={item.case} href={caseHref(item.case, "investigation")} />
      <code>{txt(item.id)}</code>
      <Time utc={item.utc} relative />
    </>
  );
}

function WaitingPanel({ items, count, onChange }: { items: WaitingItem[]; count: number; onChange: () => void }) {
  return (
    <Panel title={count ? `Waiting on you (${count})` : "Waiting on you"}>
      {items.length === 0 ? (
        <Empty>Nothing is waiting on you.</Empty>
      ) : (
        <ul className="rows waiting-list">
          {items.map((item) => (
            <li key={`${txt(item.case)}:${txt(item.kind)}:${txt(item.id)}`}>
              <WaitingLine item={item} onChange={onChange} />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
