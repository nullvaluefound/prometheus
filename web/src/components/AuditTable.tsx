import type { AuditEvent, CaseAuditEvent } from "../api";
import { decisionTone, short, txt } from "../format";
import { caseHref } from "../router";
import { CaseLink, DecisionChip, Empty, Time } from "./ui";

/** Audit rows, newest first. Intercepted and failed decisions are highlighted. */
export function AuditTable({
  events,
  showCase = false,
  empty,
}: {
  events: (AuditEvent | CaseAuditEvent)[];
  showCase?: boolean;
  empty: string;
}) {
  if (events.length === 0) return <Empty>{empty}</Empty>;
  return (
    <div className="table-wrap">
      <table className="data wide">
        <thead>
          <tr>
            <th scope="col">UTC</th>
            {showCase && <th scope="col">Case</th>}
            <th scope="col">Decision</th>
            <th scope="col">Tool or operation</th>
            <th scope="col">Audience</th>
            <th scope="col">Detail</th>
            <th scope="col">Artifact</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => {
            const tone = decisionTone(event.decision);
            const caseId = "case" in event ? event.case : undefined;
            const detail = [txt(event.reason), txt(event.operator) && `by ${txt(event.operator)}`, txt(event.address)]
              .filter(Boolean)
              .join(" · ");
            return (
              <tr key={index} className={tone === "warn" ? "row-warn" : tone === "err" ? "row-err" : undefined}>
                <td className="nowrap">
                  <Time utc={event.utc} />
                </td>
                {showCase && (
                  <td>
                    <CaseLink id={caseId} href={caseHref(caseId)} />
                  </td>
                )}
                <td>
                  <DecisionChip decision={event.decision} />
                </td>
                <td>{txt(event.tool) || txt(event.operation) ? <code>{txt(event.tool) || txt(event.operation)}</code> : <span className="muted">—</span>}</td>
                <td>{txt(event.audience) || txt(event.via) || <span className="muted">—</span>}</td>
                <td className="cell-text">{detail || <span className="muted">—</span>}</td>
                <td>{event.artifact ? <code title={txt(event.artifact)}>{short(event.artifact, 16)}</code> : <span className="muted">—</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
