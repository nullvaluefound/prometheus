import { useState } from "react";
import { api } from "../api";
import { short, txt } from "../format";
import { useResource } from "../hooks";
import { ResultView } from "./ResultView";
import { Badge, Dialog, ErrorNote, Loading, Time } from "./ui";

/** An evidence id that opens the exact tool result the broker released, for the operator. */
export function EvidenceLink({ caseId, id }: { caseId: string; id: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="btn-link mono evidence-link" onClick={() => setOpen(true)} title={`Evidence ${txt(id)}`}>
        {short(id, 10)}
      </button>
      <Dialog open={open} title={`Evidence ${short(id, 16)}`} onClose={() => setOpen(false)}>
        <EvidenceBody caseId={caseId} id={id} />
      </Dialog>
    </>
  );
}

function EvidenceBody({ caseId, id }: { caseId: string; id: string }) {
  const entry = useResource((signal) => api.evidenceEntry(caseId, id, { signal }), `evidence:${caseId}:${id}`);
  if (entry.error) return <ErrorNote message={entry.error} onRetry={entry.reload} />;
  if (!entry.data) return <Loading label="Reading the evidence…" />;
  const data = entry.data;
  return (
    <div className="stack-sm">
      <p className="muted small">
        <code>{txt(data.tool)}</code> released to the <strong>{txt(data.audience)}</strong> audience <Time utc={data.utc} />.{" "}
        {data.excerpt ? <Badge tone="warn">excerpt under a grant</Badge> : <Badge>no excerpt</Badge>} The content hashes to this id, so it is the
        exact result the model saw. Sample-derived text is untrusted.
      </p>
      <ResultView value={data.reply} />
    </div>
  );
}
