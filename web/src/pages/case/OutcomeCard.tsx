import { api, type Finding, type Outcome } from "../../api";
import { Empty, ErrorNote, Loading, Panel, Time } from "../../components/ui";
import { fmtCount, fmtDuration, isRecord, list, txt } from "../../format";
import { useResource } from "../../hooks";
import type { CaseContext } from "../CaseView";

const DECISIONS = ["dispatched", "completed", "intercepted", "failed", "investigation_write"] as const;

/** Metadata about how the case went: calls, grants, proposals, findings and tokens. The baseline for later changes. */
export function OutcomeCard({ ctx }: { ctx: CaseContext }) {
  const outcome = useResource((signal) => api.outcome(ctx.id, { signal }), `outcome:${ctx.id}`, () => 60000, [
    `case:${ctx.id}`,
    `investigation:${ctx.id}`,
    `requests:${ctx.id}`,
    "tasks",
  ]);
  const data = outcome.data;
  const findings = list<Finding>(ctx.detail.ledger?.findings).filter(isRecord);
  const kinds = new Map<string, number>();
  for (const finding of findings) if (!finding.superseded_by) kinds.set(txt(finding.kind), (kinds.get(txt(finding.kind)) ?? 0) + 1);

  return (
    <Panel title="Outcome">
      {outcome.error && !data && <ErrorNote message={outcome.error} onRetry={outcome.reload} />}
      {!data && !outcome.error && <Loading label="Counting the case's outcome…" />}
      {data && <OutcomeBody data={data} kinds={kinds} />}
    </Panel>
  );
}

function OutcomeBody({ data, kinds }: { data: Outcome; kinds: Map<string, number> }) {
  const tools = isRecord(data.tools) ? Object.entries(data.tools) : [];
  const tokens = list<Outcome["tokens"][number]>(data.tokens);
  const grants = data.grants;
  const candidates = data.candidates;
  return (
    <div className="stack-sm">
      <div className="stats stats-compact">
        <section className="stat">
          <p className="stat-label">Grants</p>
          <p className="stat-value">{fmtCount(grants?.issued)}</p>
          <p className="stat-detail muted">
            issued · {fmtCount(grants?.requested)} requested by models, {fmtCount(grants?.approved)} approved, {fmtCount(grants?.denied)} denied
          </p>
        </section>
        <section className="stat">
          <p className="stat-label">Proposed findings</p>
          <p className="stat-value">{fmtCount(candidates?.total)}</p>
          <p className="stat-detail muted">
            {fmtCount(candidates?.passed)} references resolve, {fmtCount(candidates?.failed)} failed · {fmtCount(candidates?.recorded)} recorded,{" "}
            {fmtCount(candidates?.rejected)} rejected, {fmtCount(candidates?.proposed)} waiting
          </p>
        </section>
        <section className="stat">
          <p className="stat-label">Findings</p>
          <p className="stat-value">{fmtCount([...kinds.values()].reduce((sum, value) => sum + value, 0))}</p>
          <p className="stat-detail muted">
            {kinds.size === 0 ? "none current" : [...kinds.entries()].map(([kind, value]) => `${value} ${kind}`).join(", ")}
          </p>
        </section>
        <section className="stat">
          <p className="stat-label">Time span</p>
          <p className="stat-value">{data.first_utc && data.last_utc ? fmtDuration(data.first_utc, data.last_utc) : "—"}</p>
          <p className="stat-detail muted">
            {data.first_utc ? (
              <>
                from <Time utc={data.first_utc} /> · {fmtCount(data.model_sessions)} model sessions
              </>
            ) : (
              "no audit yet"
            )}
          </p>
        </section>
      </div>
      <div className="columns">
        <div>
          <p className="label">Tool calls by decision</p>
          {tools.length === 0 ? (
            <Empty>No model tool calls yet.</Empty>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">Tool</th>
                    {DECISIONS.map((decision) => (
                      <th scope="col" key={decision} className="num">
                        {decision.replace("_", " ")}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tools.map(([tool, row]) => (
                    <tr key={tool}>
                      <td>
                        <code>{tool}</code>
                      </td>
                      {DECISIONS.map((decision) => (
                        <td key={decision} className="num">
                          {fmtCount(isRecord(row) ? row[decision] ?? 0 : 0)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div>
          <p className="label">Model tokens</p>
          {tokens.length === 0 ? (
            <Empty>No model usage recorded yet.</Empty>
          ) : (
            <ul className="rows">
              {tokens.map((row) => (
                <li key={`${txt(row.provider)}/${txt(row.locality)}`}>
                  <span>
                    <code>{txt(row.provider)}</code> <span className={row.locality === "cloud" ? "chip chip-warn chip-nodot" : "chip chip-muted chip-nodot"}>{txt(row.locality)}</span>
                  </span>
                  <span className="muted small">
                    {fmtCount(row.input)} in · {fmtCount(row.output)} out · {fmtCount(row.sessions)} sessions
                  </span>
                </li>
              ))}
            </ul>
          )}
          {isRecord(data.denials) && Object.keys(data.denials).length > 0 && (
            <>
              <p className="label">Refusals by reason</p>
              <ul className="rows">
                {Object.entries(data.denials).map(([reason, value]) => (
                  <li key={reason}>
                    <code>{reason}</code>
                    <span>{fmtCount(value)}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
