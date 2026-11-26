import { useState } from "react";
import { api, type CaseRow } from "../api";
import { NewCaseDialog } from "../components/NewCaseDialog";
import { CaseLink, Empty, ErrorNote, Loading, RefreshButton, StatusChip, Time } from "../components/ui";
import { fmtCount, list, txt } from "../format";
import { useDocumentTitle, useResource } from "../hooks";
import { caseHref } from "../router";

export function CasesPage() {
  useDocumentTitle("Cases");
  const cases = useResource(
    (signal) => api.cases({ signal }),
    "cases",
    (data) => (list<CaseRow>(data.cases).some((item) => item.status === "Pending") ? 3000 : null),
  );
  const [creating, setCreating] = useState(false);
  const rows = list<CaseRow>(cases.data?.cases);

  return (
    <>
      <p className="crumb">
        <a href="#/">Forge</a> / Cases
      </p>
      <div className="page-head">
        <h1>Cases</h1>
        <div className="page-actions">
          <RefreshButton onClick={cases.reload} busy={cases.loading && Boolean(cases.data)} />
          <button type="button" onClick={() => setCreating(true)}>
            New case
          </button>
        </div>
      </div>
      <NewCaseDialog open={creating} onClose={() => setCreating(false)} onCreated={cases.reload} />
      {cases.error && <ErrorNote message={cases.error} onRetry={cases.reload} />}
      {!cases.data && !cases.error && <Loading label="Loading cases…" />}
      {cases.data && (
        <section className="panel" aria-label="Case list">
          {rows.length === 0 ? (
            <Empty>No cases yet. Use New case to open one.</Empty>
          ) : (
            <div className="table-wrap">
              <table className="data wide">
                <thead>
                  <tr>
                    <th scope="col">Case</th>
                    <th scope="col">Title</th>
                    <th scope="col">Status</th>
                    <th scope="col">Model</th>
                    <th scope="col">Cloud</th>
                    <th scope="col" className="num">
                      Artifacts
                    </th>
                    <th scope="col" className="num">
                      Findings
                    </th>
                    <th scope="col">Last activity</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((item) => (
                    <tr key={txt(item.id)}>
                      <td>
                        <CaseLink id={item.id} href={caseHref(item.id)} />
                      </td>
                      <td className="cell-text">{txt(item.title) || <span className="muted">Untitled</span>}</td>
                      <td>
                        <StatusChip status={item.status} />
                      </td>
                      <td>{item.model ? <code>{txt(item.model)}</code> : <span className="muted">None</span>}</td>
                      <td>{item.allow_cloud ? <span className="chip chip-warn chip-nodot">Allowed</span> : <span className="muted">Local only</span>}</td>
                      <td className="num">{item.artifacts === null ? <span className="muted">—</span> : fmtCount(item.artifacts)}</td>
                      <td className="num">{item.findings === null ? <span className="muted">—</span> : fmtCount(item.findings)}</td>
                      <td className="nowrap">
                        <Time utc={item.updated_utc} relative />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="muted small">Artifact and finding counts come from the last ledger read. Open a case to read its ledger again.</p>
        </section>
      )}
    </>
  );
}
