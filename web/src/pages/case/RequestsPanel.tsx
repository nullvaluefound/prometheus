import { useState } from "react";
import { api, type GrantRequest } from "../../api";
import { useToast } from "../../components/toast";
import { Badge, ConfirmButton, Empty, ErrorNote, Loading, Panel, Time } from "../../components/ui";
import { isRecord, list, short, txt } from "../../format";
import { errorMessage, useResource } from "../../hooks";
import type { CaseContext } from "../CaseView";

function selectorText(request: GrantRequest): string {
  return isRecord(request.selector)
    ? Object.entries(request.selector)
        .map(([key, value]) => `${key}=${txt(value)}`)
        .join(" ")
    : "";
}

/** Grant requests the Forge filed from broker denials. Approving issues a grant for exactly the denied call. */
export function RequestsPanel({ ctx }: { ctx: CaseContext }) {
  const requests = useResource(
    (signal) => api.requests(ctx.id, { signal }),
    `requests:${ctx.id}`,
    (data) => (list<GrantRequest>(data.requests).some((row) => row.state === "pending") ? 10000 : 30000),
  );
  const rows = list<GrantRequest>(requests.data?.requests).filter(isRecord);
  const pending = rows.filter((row) => row.state === "pending");
  const decided = rows.filter((row) => row.state !== "pending").slice(0, 10);
  const toast = useToast();
  const reload = () => {
    requests.reload();
    ctx.reload();
  };
  const denyAll = async () => {
    try {
      const { denied } = await api.denyAllRequests(ctx.id);
      toast(`Denied ${list(denied).length} request${list(denied).length === 1 ? "" : "s"}.`, "ok");
      reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <Panel
      title={pending.length ? `Grant requests waiting on you (${pending.length})` : "Grant requests"}
      actions={
        pending.length > 1 ? <ConfirmButton label="Deny all" prompt={`Deny all ${pending.length} requests?`} confirmLabel="Deny all" onConfirm={denyAll} /> : undefined
      }
    >
      <p className="muted small">
        When the broker refuses a model's call because it needs an excerpt grant, the Forge files a request for exactly that call. Approving
        grants that call, for the model's own audience, for the minutes you choose. The model's reason is untrusted text written by the model.
      </p>
      {requests.error && !requests.data && <ErrorNote message={requests.error} onRetry={requests.reload} />}
      {!requests.data && !requests.error && <Loading label="Loading grant requests…" />}
      {requests.data && pending.length === 0 && <Empty>No grant requests are waiting.</Empty>}
      {pending.length > 0 && (
        <ul className="rows request-list">
          {pending.map((row) => (
            <li key={txt(row.id)}>
              <PendingRequest ctx={ctx} request={row} onDecided={reload} />
            </li>
          ))}
        </ul>
      )}
      {decided.length > 0 && (
        <>
          <p className="label">Recently decided</p>
          <ul className="rows">
            {decided.map((row) => (
              <li key={txt(row.id)} className="request-decided">
                <Badge tone={row.state === "approved" ? "ok" : "muted"}>{txt(row.state)}</Badge>
                <code>{txt(row.tool)}</code>
                <code title={txt(row.artifact)}>{short(row.artifact, 12)}</code>
                {selectorText(row) && <code>{selectorText(row)}</code>}
                <span className="muted small">
                  by {txt(row.decided_by)} <Time utc={row.decided_utc} relative />
                  {row.grant && ` · grant ${short(row.grant, 8)}`}
                  {row.note && ` · ${txt(row.note)}`}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}

function PendingRequest({ ctx, request, onDecided }: { ctx: CaseContext; request: GrantRequest; onDecided: () => void }) {
  const toast = useToast();
  const [minutes, setMinutes] = useState("10");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const closed = ctx.detail.status === "Closed";
  const disabled = (ctx.inactive !== null && !closed) || busy;
  const flags = list<string>(request.flags);

  const decide = async (decision: "approve" | "deny") => {
    const span = Number(minutes);
    if (decision === "approve" && (!Number.isInteger(span) || span < 1 || span > 60)) {
      toast("Minutes must be a whole number from 1 to 60.", "err");
      return;
    }
    setBusy(true);
    try {
      const decided = await api.decideRequest(ctx.id, request.id, decision === "approve" ? { decision, minutes: span } : { decision, note: note.trim() || undefined });
      toast(decision === "approve" ? `Granted for ${span} min as ${short(decided.grant, 8)}.` : "Request denied.", "ok");
      onDecided();
    } catch (error) {
      toast(errorMessage(error), "err");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="request">
      <div className="request-call">
        <code>{txt(request.tool)}</code>
        <code title={txt(request.artifact)}>{short(request.artifact, 16)}</code>
        {selectorText(request) ? <code>{selectorText(request)}</code> : <span className="muted">whole tool call</span>}
        <Badge tone={request.audience === "mcp" ? "warn" : "muted"} title={request.audience === "mcp" ? "A cloud or MCP model would receive the excerpt" : "The local model runner would receive the excerpt"}>
          {txt(request.audience)}
        </Badge>
        <span className="muted small">
          filed <Time utc={request.created_utc} relative />
        </span>
      </div>
      {request.reason ? (
        <p className="request-reason">
          <span className="muted small">Model's reason (untrusted):</span> {txt(request.reason)}
        </p>
      ) : (
        <p className="muted small">The model gave no reason.</p>
      )}
      {flags.length > 0 && (
        <p className="note note-warn small">
          The reason names values the case never showed this session: {flags.map((value) => short(value, 16)).join(", ")}. They are model-derived and
          unverified.
        </p>
      )}
      <div className="request-actions">
        <label className="field field-inline">
          <span>Minutes</span>
          <input type="number" inputMode="numeric" min={1} max={60} step={1} value={minutes} onChange={(event) => setMinutes(event.target.value)} disabled={disabled} />
        </label>
        <button type="button" className="btn-small" onClick={() => void decide("approve")} disabled={disabled || closed}>
          Approve
        </button>
        <label className="field field-inline">
          <span>Note</span>
          <input type="text" maxLength={200} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Optional reason for denying" disabled={disabled} />
        </label>
        <ConfirmButton label="Deny" prompt="Deny this request?" confirmLabel="Deny" onConfirm={() => decide("deny")} disabled={disabled} />
      </div>
    </div>
  );
}
