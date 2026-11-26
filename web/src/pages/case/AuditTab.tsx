import { useState } from "react";
import { api, type AuditEvent } from "../../api";
import { AuditTable } from "../../components/AuditTable";
import { ErrorNote, Loading, Panel, RefreshButton } from "../../components/ui";
import { decisionTone, list } from "../../format";
import { useResource } from "../../hooks";
import type { CaseContext } from "../CaseView";

export function AuditTab({ ctx }: { ctx: CaseContext }) {
  const audit = useResource((signal) => api.audit(ctx.id, { signal }), `audit:${ctx.id}`);
  const [notable, setNotable] = useState(false);
  const events = list<AuditEvent>(audit.data?.audit);
  const flagged = events.filter((event) => decisionTone(event.decision) === "warn" || decisionTone(event.decision) === "err");
  const shown = notable ? flagged : events;

  return (
    <Panel
      title="Audit"
      actions={
        <>
          <label className="check">
            <input type="checkbox" checked={notable} onChange={(event) => setNotable(event.target.checked)} />
            <span>Only intercepted and failed ({flagged.length})</span>
          </label>
          <RefreshButton onClick={audit.reload} busy={audit.loading && Boolean(audit.data)} />
        </>
      }
    >
      {audit.error && <ErrorNote message={audit.error} onRetry={audit.reload} />}
      {!audit.data && !audit.error && <Loading label="Loading the audit trail…" />}
      {audit.data && (
        <AuditTable
          events={shown}
          empty={notable ? "No intercepted or failed events in the newest 200." : "No audit events yet."}
        />
      )}
      <p className="muted small">The newest 200 events, newest first. The broker records every call before dispatch.</p>
    </Panel>
  );
}
