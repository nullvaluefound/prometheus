import { Fragment, useState } from "react";
import { api, type CaseRow, type Task } from "../api";
import { TaskOutcome } from "../components/ResultView";
import { useToast } from "../components/toast";
import { CaseLink, Chevron, Empty, ErrorNote, Loading, RefreshButton, TaskChip, Time } from "../components/ui";
import { CASE_ID, fmtDuration, isRecord, list, txt } from "../format";
import { errorMessage, isTerminal, useDocumentTitle, useResource } from "../hooks";
import { caseHref, tasksHref } from "../router";

const KIND_LABEL: Record<string, string> = {
  create_case: "Create case",
  ingest: "Ingest",
  tool: "Tool",
  chat: "Chat",
  model_test: "Model test",
  report: "Report",
};

export function TasksPage({ initialFilter }: { initialFilter: string | null }) {
  useDocumentTitle("Tasks");
  const toast = useToast();
  const [filter, setFilter] = useState(initialFilter ?? "");
  const tasks = useResource(
    (signal) => api.tasks(filter || null, { signal }),
    `tasks:${filter}`,
    (data) => (list<Task>(data.tasks).some((task) => !isTerminal(task.state)) ? 2000 : null),
  );
  const cases = useResource((signal) => api.cases({ signal }), "cases");
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [cancelling, setCancelling] = useState<string | null>(null);
  const rows = list<Task>(tasks.data?.tasks).filter(isRecord);
  const caseIds = list<CaseRow>(cases.data?.cases)
    .map((item) => txt(item.id))
    .filter((id) => CASE_ID.test(id));
  if (filter && !caseIds.includes(filter)) caseIds.unshift(filter);
  const active = rows.filter((task) => !isTerminal(task.state)).length;

  const changeFilter = (value: string) => {
    setFilter(value);
    window.history.replaceState(null, "", tasksHref(value || null));
  };

  const toggle = (id: string) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const cancel = async (task: Task) => {
    setCancelling(task.id);
    try {
      await api.cancelTask(task.id);
      toast("Task cancelled.", "ok");
      tasks.reload();
    } catch (error) {
      toast(errorMessage(error), "err");
      tasks.reload();
    } finally {
      setCancelling(null);
    }
  };

  return (
    <>
      <p className="crumb">
        <a href="#/">Forge</a> / Tasks
      </p>
      <div className="page-head">
        <h1>Tasks</h1>
        <div className="page-actions">
          <label className="field field-inline">
            <span>Case</span>
            <select value={filter} onChange={(event) => changeFilter(event.target.value)}>
              <option value="">All cases</option>
              {caseIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
          </label>
          <RefreshButton onClick={tasks.reload} busy={tasks.loading && Boolean(tasks.data)} />
        </div>
      </div>
      <p className="muted">
        Tasks run one at a time, in order. Newest first, up to 100.
        {active > 0 && ` ${active} active; this list refreshes every 2 seconds.`}
      </p>
      {tasks.error && <ErrorNote message={tasks.error} onRetry={tasks.reload} />}
      {!tasks.data && !tasks.error && <Loading label="Loading tasks…" />}
      {tasks.data && (
        <section className="panel" aria-label="Task list">
          {rows.length === 0 ? (
            <Empty>{filter ? "No tasks for this case yet." : "No tasks yet."}</Empty>
          ) : (
            <div className="table-wrap">
              <table className="data wide tasks-table">
                <thead>
                  <tr>
                    <th scope="col">Task</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Case</th>
                    <th scope="col">State</th>
                    <th scope="col">Operator</th>
                    <th scope="col">Created</th>
                    <th scope="col">Duration</th>
                    <th scope="col">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((task) => {
                    const open = expanded.has(task.id);
                    const detailId = `task-${txt(task.id)}`;
                    return (
                      <Fragment key={txt(task.id)}>
                        <tr className={task.state === "failed" ? "row-err" : undefined}>
                          <td>
                            <button
                              type="button"
                              className="btn-disclosure"
                              aria-expanded={open}
                              aria-controls={open ? detailId : undefined}
                              onClick={() => toggle(task.id)}
                            >
                              <Chevron open={open} />
                              <span className="cell-text">{txt(task.title) || txt(task.kind)}</span>
                            </button>
                          </td>
                          <td className="nowrap">{KIND_LABEL[task.kind] ?? txt(task.kind)}</td>
                          <td>{task.case ? <CaseLink id={task.case} href={caseHref(task.case)} /> : <span className="muted">—</span>}</td>
                          <td>
                            <TaskChip state={task.state} />
                          </td>
                          <td>{txt(task.operator)}</td>
                          <td className="nowrap">
                            <Time utc={task.created_utc} relative />
                          </td>
                          <td className="nowrap">{fmtDuration(task.started_utc, task.finished_utc) || <span className="muted">—</span>}</td>
                          <td>
                            {task.state === "queued" && (
                              <button
                                type="button"
                                className="btn-secondary btn-small"
                                onClick={() => cancel(task)}
                                disabled={cancelling === task.id}
                              >
                                Cancel
                              </button>
                            )}
                          </td>
                        </tr>
                        {open && (
                          <tr className="detail-row" id={detailId}>
                            <td colSpan={8}>
                              <div className="task-detail">
                                <p className="muted small">
                                  Task <code>{txt(task.id)}</code> · created <Time utc={task.created_utc} />
                                  {task.started_utc && (
                                    <>
                                      {" "}
                                      · started <Time utc={task.started_utc} />
                                    </>
                                  )}
                                  {task.finished_utc && (
                                    <>
                                      {" "}
                                      · finished <Time utc={task.finished_utc} />
                                    </>
                                  )}
                                </p>
                                {isTerminal(task.state) ? (
                                  <TaskOutcome task={task} />
                                ) : (
                                  <p className="muted">{task.state === "queued" ? "Waiting in the queue." : "Running now."}</p>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </>
  );
}
