import { useState } from "react";
import type { Finding } from "../../api";
import { Empty, Note, Panel } from "../../components/ui";
import { isRecord, list, short, txt } from "../../format";
import type { CaseContext } from "../CaseView";

export function FindingsTab({ ctx }: { ctx: CaseContext }) {
  const ledger = ctx.detail.ledger;
  const findings = list<Finding>(ledger?.findings).filter(isRecord);
  const superseded = findings.filter((item) => item.superseded_by).length;
  const [showSuperseded, setShowSuperseded] = useState(true);
  const shown = showSuperseded ? findings : findings.filter((item) => !item.superseded_by);

  return (
    <Panel
      title="Findings"
      actions={
        superseded > 0 && (
          <label className="check">
            <input type="checkbox" checked={showSuperseded} onChange={(event) => setShowSuperseded(event.target.checked)} />
            <span>Show {superseded} superseded</span>
          </label>
        )
      }
    >
      {!ledger ? (
        <Note tone="warn">The evidence ledger is unavailable. Check the Docker engine and run verify.</Note>
      ) : shown.length === 0 ? (
        <Empty>No findings recorded yet. Analysts record findings through the evidence workflow.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="data wide">
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Kind</th>
                <th scope="col">Confidence</th>
                <th scope="col">Claim</th>
                <th scope="col">Evidence</th>
                <th scope="col">Artifacts</th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, 500).map((item, index) => (
                <tr key={`${txt(item.id)}-${index}`} className={item.superseded_by ? "row-muted" : undefined}>
                  <td className="nowrap">
                    <code>{txt(item.id)}</code>
                    {item.superseded_by && (
                      <span className="muted small block">
                        superseded by <code>{txt(item.superseded_by)}</code>
                      </span>
                    )}
                  </td>
                  <td>{txt(item.kind)}</td>
                  <td>{txt(item.confidence)}</td>
                  <td className="cell-text claim">{txt(item.claim)}</td>
                  <td>
                    <ul className="plain">
                      {list(item.evidence)
                        .slice(0, 12)
                        .map((value, position) => (
                          <li key={position} className="cell-text">
                            {txt(value)}
                          </li>
                        ))}
                    </ul>
                  </td>
                  <td>
                    <ul className="plain">
                      {list(item.artifacts)
                        .slice(0, 12)
                        .map((value, position) => (
                          <li key={position}>
                            <code title={txt(value)}>{short(value, 16)}</code>
                          </li>
                        ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small">Findings are analyst claims about untrusted evidence. Check the cited evidence before relying on one.</p>
    </Panel>
  );
}
