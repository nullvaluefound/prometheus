import { useCallback, useState } from "react";
import { api, type CaseDetail, type Task, type ToolArgs } from "../api";
import { useToast } from "../components/toast";
import { ErrorNote, Loading, RefreshButton, StatusChip } from "../components/ui";
import { list, txt } from "../format";
import { errorMessage, useDocumentTitle, useResource } from "../hooks";
import { CASE_TABS, caseHref, navigate, tasksHref, type CaseTab } from "../router";
import { ArtifactsTab } from "./case/ArtifactsTab";
import { AuditTab } from "./case/AuditTab";
import { ChatTab } from "./case/ChatTab";
import { FindingsTab } from "./case/FindingsTab";
import { OverviewTab } from "./case/OverviewTab";
import { RulesTab } from "./case/RulesTab";
import { ToolsTab, type ToolRun } from "./case/ToolsTab";

export interface CaseContext {
  id: string;
  detail: CaseDetail;
  /** Why broker actions are unavailable, or null when the case is Ready. */
  inactive: string | null;
  reload: () => void;
}

function inactiveReason(detail: CaseDetail): string | null {
  switch (detail.status) {
    case "Ready":
      return null;
    case "Paused":
      return "This case is paused, so the broker refuses new actions. Resume it on the Overview tab.";
    case "Closed":
      return "This case is closed. Its ledger, report and audit stay read-only.";
    default:
      return "This case is still being set up.";
  }
}

export function CaseView({ id, tab }: { id: string; tab: CaseTab }) {
  const detail = useResource(
    (signal) => api.caseDetail(id, { signal }),
    `case:${id}`,
    (data) => (data.status === "Pending" ? 3000 : null),
  );
  const policy = useResource((signal) => api.policy({ signal }), "policy");
  const toast = useToast();
  const [runs, setRuns] = useState<ToolRun[]>([]);
  const [preset, setPreset] = useState<string | null>(null);
  const [reportTask, setReportTask] = useState<Task | null>(null);
  const [draft, setDraft] = useState("");
  const data = detail.data;
  useDocumentTitle(txt(data?.title) || id);

  const runTool = useCallback(
    async (tool: string, args: ToolArgs) => {
      const { task } = await api.runTool(id, tool, args);
      setRuns((all) => [{ key: task.id, task, tool, args }, ...all.filter((run) => run.key !== task.id)].slice(0, 25));
      return task;
    },
    [id],
  );

  const openTools = useCallback(
    (artifact: string) => {
      setPreset(artifact);
      navigate(caseHref(id, "tools") ?? "#/cases");
    },
    [id],
  );

  const summarize = useCallback(
    async (artifact: string) => {
      try {
        await runTool("artifact_summary", { artifact });
        setPreset(artifact);
        navigate(caseHref(id, "tools") ?? "#/cases");
      } catch (error) {
        toast(errorMessage(error), "err");
      }
    },
    [id, runTool, toast],
  );

  if (!data) {
    return (
      <>
        <Crumb id={id} />
        <h1 className="h1-case">{id}</h1>
        {detail.status === 404 ? (
          <ErrorNote message="This case does not exist or is not visible to the Forge." />
        ) : detail.error ? (
          <ErrorNote message={detail.error} onRetry={detail.reload} />
        ) : (
          <Loading label="Reading the case ledger. This can take a few seconds…" />
        )}
      </>
    );
  }

  const context: CaseContext = { id, detail: data, inactive: inactiveReason(data), reload: detail.reload };
  const artifacts = list(data.ledger?.artifacts);
  const findings = list(data.ledger?.findings);
  const counts: Partial<Record<CaseTab, number>> = {
    artifacts: artifacts.length,
    findings: findings.length,
    rules: list(data.grants).length + (typeof data.pending_requests === "number" ? data.pending_requests : 0),
  };

  return (
    <>
      <Crumb id={id} />
      <div className="page-head">
        <div className="case-heading">
          <h1 className="h1-case">{txt(data.title) || id}</h1>
          <p className="case-sub">
            <code>{id}</code>
            <StatusChip status={data.status} />
            <a href={tasksHref(id)}>Tasks for this case</a>
          </p>
        </div>
        <div className="page-actions">
          <RefreshButton onClick={detail.reload} busy={detail.loading} />
        </div>
      </div>
      {detail.error && <ErrorNote message={`Refresh failed: ${detail.error}`} onRetry={detail.reload} />}
      <nav className="tabs" aria-label="Case sections">
        {CASE_TABS.map((item) => (
          <a
            key={item.id}
            className="tab"
            href={caseHref(id, item.id) ?? "#/cases"}
            aria-current={item.id === tab ? "page" : undefined}
          >
            {item.label}
            {counts[item.id] !== undefined && counts[item.id]! > 0 && <span className="tab-count">{counts[item.id]}</span>}
          </a>
        ))}
      </nav>
      <div className="tab-panel">
        {tab === "overview" && <OverviewTab ctx={context} reportTask={reportTask} onReport={setReportTask} />}
        {tab === "artifacts" && <ArtifactsTab ctx={context} policy={policy.data} onSummary={summarize} onTools={openTools} />}
        {tab === "tools" && <ToolsTab ctx={context} policy={policy} runs={runs} runTool={runTool} preset={preset} />}
        {tab === "findings" && <FindingsTab ctx={context} />}
        {tab === "chat" && <ChatTab ctx={context} draft={draft} setDraft={setDraft} />}
        {tab === "rules" && <RulesTab ctx={context} policy={policy} />}
        {tab === "audit" && <AuditTab ctx={context} />}
      </div>
    </>
  );
}

function Crumb({ id }: { id: string }) {
  return (
    <p className="crumb">
      <a href="#/">Forge</a> / <a href="#/cases">Cases</a> / <span>{id}</span>
    </p>
  );
}
