import { useState } from "react";
import { api, type CaseRow, type Investigation, type Task } from "../../api";
import { useToast } from "../../components/toast";
import { Empty, Panel, Time } from "../../components/ui";
import { isRecord, list, short, txt } from "../../format";
import { errorMessage, isTerminal, useResource, useTask } from "../../hooks";
import type { CaseContext } from "../CaseView";

/** Prior cases whose recorded findings, not bytes, models see read-only in case_overview. */
export function LinksPanel({ ctx, data, reload }: { ctx: CaseContext; data: Investigation; reload: () => void }) {
  const toast = useToast();
  const cases = useResource((signal) => api.cases({ signal }), "cases");
  const linked = list<{ case: string; refreshed_utc: string }>(data.links).filter(isRecord);
  const [chosen, setChosen] = useState<Set<string>>(() => new Set(linked.map((row) => row.case)));
  const [pending, setPending] = useState<Task | null>(null);
  const tracked = useTask(pending?.id ?? null, {
    initial: pending,
    onSettled: (task) => {
      toast(task.state === "failed" ? txt(task.error) || "Linking failed." : "Linked cases refreshed.", task.state === "failed" ? "err" : "ok");
      reload();
    },
  });
  const busy = tracked.task !== null && !isTerminal(tracked.task.state);
  const others = list<CaseRow>(cases.data?.cases).filter((row) => row.id !== ctx.id && row.status !== "Pending");
  const inherited = list<{ case: string; finding: string; kind: string; confidence: string; claim: string }>(data.inherited);
  const closed = ctx.detail.status === "Closed";

  const save = async () => {
    try {
      setPending((await api.setLinks(ctx.id, [...chosen])).task);
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <Panel title="Linked prior cases">
      <p className="muted small">
        Models see the recorded findings of linked cases in <code>case_overview</code>, marked inherited and citing their own case's artifacts.
        No artifact or excerpt crosses cases. Saving takes a snapshot of each linked ledger; save again to refresh it.
      </p>
      {others.length === 0 ? (
        <Empty>No other cases to link.</Empty>
      ) : (
        <div className="check-grid">
          {others.map((row) => (
            <label className="check" key={row.id}>
              <input
                type="checkbox"
                checked={chosen.has(row.id)}
                disabled={closed}
                onChange={(event) =>
                  setChosen((current) => {
                    const next = new Set(current);
                    if (event.target.checked) next.add(row.id);
                    else next.delete(row.id);
                    return next;
                  })
                }
              />
              <span>
                <code>{row.id}</code> {txt(row.title)}
              </span>
            </label>
          ))}
        </div>
      )}
      {!closed && (
        <div className="form-actions">
          <button type="button" className="btn-secondary btn-small" disabled={busy || chosen.size > 8} onClick={() => void save()}>
            {busy ? "Reading ledgers…" : "Save links"}
          </button>
          {linked.length > 0 && (
            <span className="muted small">
              Snapshot <Time utc={linked[0].refreshed_utc} relative />
            </span>
          )}
        </div>
      )}
      {inherited.length > 0 && (
        <ul className="rows">
          {inherited.slice(0, 50).map((row, index) => (
            <li key={`${row.case}-${row.finding}-${index}`}>
              <span>
                <code>{txt(row.case)}</code> <code>{txt(row.finding)}</code> <span className="muted small">{txt(row.kind)}, {txt(row.confidence)}</span>
              </span>
              <span className="cell-text">{short(row.claim, 160)}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
