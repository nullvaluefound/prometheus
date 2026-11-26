import { useMemo, useState, type FormEvent } from "react";
import { api, type Artifact, type Policy, type PolicyTool, type Task, type ToolArgs } from "../../api";
import { TaskOutcome } from "../../components/ResultView";
import { useToast } from "../../components/toast";
import { Badge, Empty, ErrorNote, Loading, Note, Panel, TaskChip, Time } from "../../components/ui";
import {
  ADDRESS,
  ADDRESS_PATTERN,
  DIGEST,
  DIGEST_PATTERN,
  LIMIT_DEFAULT,
  LIMIT_MAX,
  OFFSET_MAX,
  fmtBytes,
  fmtDuration,
  isRecord,
  list,
  short,
  txt,
} from "../../format";
import { errorMessage, isTerminal, useTask, type Resource } from "../../hooks";
import type { CaseContext } from "../CaseView";

export interface ToolRun {
  key: string;
  task: Task;
  tool: string;
  args: ToolArgs;
}

export function usableTools(policy: Policy | undefined): PolicyTool[] {
  if (!policy) return [];
  const denied = new Set(list<string>(policy.denied));
  return list<PolicyTool>(policy.tools).filter((tool) => isRecord(tool) && typeof tool.name === "string" && !denied.has(tool.name));
}

export function ToolBadges({ tool }: { tool: PolicyTool }) {
  return (
    <span className="badges">
      {tool.excerpt_only && (
        <Badge tone="warn" title="The broker withholds this tool's output from models without an active operator grant.">
          Excerpt only · needs grant
        </Badge>
      )}
      {tool.paged && <Badge tone="info">Paged</Badge>}
      {tool.addressed && <Badge tone="info">Addressed</Badge>}
      {typeof tool.timeout_s === "number" && <Badge>{tool.timeout_s}s timeout</Badge>}
    </span>
  );
}

export function parseSelector(tool: PolicyTool, address: string, offset: string, limit: string): { args: Omit<ToolArgs, "artifact">; error?: string } {
  const args: Omit<ToolArgs, "artifact"> = {};
  if (tool.addressed) {
    const value = address.trim().toLowerCase();
    if (!ADDRESS.test(value)) return { args, error: "Enter an address as 0x followed by 1 to 16 hex digits." };
    args.address = value;
  }
  if (tool.paged) {
    const from = Number(offset);
    const count = Number(limit);
    if (!Number.isInteger(from) || from < 0 || from > OFFSET_MAX) return { args, error: `Offset must be a whole number from 0 to ${OFFSET_MAX}.` };
    if (!Number.isInteger(count) || count < 1 || count > LIMIT_MAX) return { args, error: `Limit must be a whole number from 1 to ${LIMIT_MAX}.` };
    args.offset = from;
    args.limit = count;
  }
  return { args };
}

export function SelectorFields({
  tool,
  address,
  offset,
  limit,
  setAddress,
  setOffset,
  setLimit,
  disabled,
}: {
  tool: PolicyTool | undefined;
  address: string;
  offset: string;
  limit: string;
  setAddress: (value: string) => void;
  setOffset: (value: string) => void;
  setLimit: (value: string) => void;
  disabled?: boolean;
}) {
  if (!tool) return null;
  return (
    <>
      {tool.addressed && (
        <label className="field">
          <span>Address</span>
          <input
            className="mono"
            name="address"
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            pattern={ADDRESS_PATTERN}
            maxLength={18}
            placeholder="0x401000"
            required
            autoComplete="off"
            spellCheck={false}
            disabled={disabled}
          />
        </label>
      )}
      {tool.paged && (
        <>
          <label className="field">
            <span>Offset</span>
            <input
              type="number"
              name="offset"
              inputMode="numeric"
              min={0}
              max={OFFSET_MAX}
              step={1}
              value={offset}
              onChange={(event) => setOffset(event.target.value)}
              required
              disabled={disabled}
            />
          </label>
          <label className="field">
            <span>Limit</span>
            <input
              type="number"
              name="limit"
              inputMode="numeric"
              min={1}
              max={LIMIT_MAX}
              step={1}
              value={limit}
              onChange={(event) => setLimit(event.target.value)}
              required
              disabled={disabled}
            />
          </label>
        </>
      )}
    </>
  );
}

/** The selected artifact, falling back to the first ledger artifact when the selection is not listed. */
export function chosenArtifact(artifacts: Artifact[], selected: string): string {
  if (artifacts.length === 0 || artifacts.some((item) => item.sha256 === selected)) return selected;
  return artifacts[0].sha256;
}

export function ArtifactPicker({
  artifacts,
  value,
  onChange,
  disabled,
}: {
  artifacts: Artifact[];
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  if (artifacts.length === 0) {
    return (
      <label className="field">
        <span>Artifact SHA-256</span>
        <input
          className="mono"
          name="artifact"
          value={value}
          onChange={(event) => onChange(event.target.value.trim().toLowerCase())}
          pattern={DIGEST_PATTERN}
          maxLength={64}
          required
          autoComplete="off"
          spellCheck={false}
          disabled={disabled}
        />
      </label>
    );
  }
  return (
    <label className="field">
      <span>Artifact</span>
      <select className="mono" name="artifact" value={value} onChange={(event) => onChange(event.target.value)} required disabled={disabled}>
        {artifacts.map((item) => (
          <option key={item.sha256} value={item.sha256}>
            {short(item.sha256, 16)} · {fmtBytes(item.size)}
            {list<{ source?: unknown }>(item.provenance)[0]?.source ? ` · ${txt(list<{ source?: unknown }>(item.provenance)[0].source).slice(0, 40)}` : ""}
          </option>
        ))}
      </select>
    </label>
  );
}

export function ToolsTab({
  ctx,
  policy,
  runs,
  runTool,
  preset,
}: {
  ctx: CaseContext;
  policy: Resource<Policy>;
  runs: ToolRun[];
  runTool: (tool: string, args: ToolArgs) => Promise<Task>;
  preset: string | null;
}) {
  const artifacts = useMemo(
    () => list<Artifact>(ctx.detail.ledger?.artifacts).filter((item) => isRecord(item) && DIGEST.test(txt(item.sha256))),
    [ctx.detail.ledger],
  );
  const tools = usableTools(policy.data);
  const [artifact, setArtifact] = useState(() =>
    preset && (artifacts.length === 0 || artifacts.some((item) => item.sha256 === preset)) ? preset : (artifacts[0]?.sha256 ?? ""),
  );
  const [toolName, setToolName] = useState("artifact_summary");
  const [address, setAddress] = useState("");
  const [offset, setOffset] = useState("0");
  const [limit, setLimit] = useState(String(LIMIT_DEFAULT));
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const toast = useToast();
  const tool = tools.find((item) => item.name === toolName) ?? tools[0];
  const chosen = chosenArtifact(artifacts, artifact);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!tool) return;
    const digest = chosen.trim().toLowerCase();
    if (!DIGEST.test(digest)) {
      setError("Choose an artifact by its SHA-256.");
      return;
    }
    const parsed = parseSelector(tool, address, offset, limit);
    if (parsed.error) {
      setError(parsed.error);
      return;
    }
    setSubmitting(true);
    try {
      await runTool(tool.name, { artifact: digest, ...parsed.args });
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSubmitting(false);
    }
  };

  const nextPage = async (run: ToolRun) => {
    const offsetNow = run.args.offset ?? 0;
    const step = run.args.limit ?? LIMIT_DEFAULT;
    const next = Math.min(offsetNow + step, OFFSET_MAX);
    try {
      await runTool(run.tool, { ...run.args, offset: next });
    } catch (failure) {
      toast(errorMessage(failure), "err");
    }
  };

  return (
    <div className="stack">
      <Panel title="Run a tool">
        {policy.error && !policy.data && <ErrorNote message={policy.error} onRetry={policy.reload} />}
        {!policy.data && !policy.error && <Loading label="Loading the tool policy…" />}
        {ctx.inactive && <Note tone="warn">{ctx.inactive}</Note>}
        {policy.data && (
          <form className="stack-sm" onSubmit={submit} noValidate>
            {error && (
              <p className="note note-err" role="alert">
                {error}
              </p>
            )}
            <div className="form-grid">
              <ArtifactPicker artifacts={artifacts} value={chosen} onChange={setArtifact} disabled={ctx.inactive !== null} />
              <label className="field">
                <span>Tool</span>
                <select className="mono" name="tool" value={tool?.name ?? ""} onChange={(event) => setToolName(event.target.value)} disabled={ctx.inactive !== null}>
                  {tools.map((item) => (
                    <option key={item.name} value={item.name}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
              <SelectorFields
                tool={tool}
                address={address}
                offset={offset}
                limit={limit}
                setAddress={setAddress}
                setOffset={setOffset}
                setLimit={setLimit}
                disabled={ctx.inactive !== null}
              />
            </div>
            {tool && (
              <div className="tool-about">
                <p>{txt(tool.description)}</p>
                <ToolBadges tool={tool} />
                {tool.excerpt_only && (
                  <p className="muted small">This is an operator inspection, so the result includes the excerpt. Models see it only under a grant.</p>
                )}
              </div>
            )}
            <div className="form-actions">
              <button type="submit" disabled={submitting || !tool || ctx.inactive !== null}>
                {submitting ? "Queuing…" : "Run"}
              </button>
              <span className="muted small">Runs are queued tasks. Results are untrusted evidence, shown as text.</span>
            </div>
          </form>
        )}
      </Panel>

      <Panel title="Runs this session">
        {runs.length === 0 ? (
          <Empty>No tool runs yet. Results appear here, newest first, and on the Tasks page.</Empty>
        ) : (
          <ol className="runs">
            {runs.map((run) => (
              <li key={run.key}>
                <ToolRunCard run={run} paged={tools.find((item) => item.name === run.tool)?.paged ?? false} onNextPage={nextPage} />
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

function ToolRunCard({ run, paged, onNextPage }: { run: ToolRun; paged: boolean; onNextPage: (run: ToolRun) => void }) {
  const tracked = useTask(run.task.id, { initial: run.task });
  const task = tracked.task ?? run.task;
  const [open, setOpen] = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const toast = useToast();
  const result = task.result;
  const hasMore = paged && task.state === "succeeded" && isRecord(result) && result.has_more === true;
  const selector = [
    run.args.address && `address ${run.args.address}`,
    run.args.offset !== undefined && `offset ${run.args.offset}`,
    run.args.limit !== undefined && `limit ${run.args.limit}`,
  ]
    .filter(Boolean)
    .join(" · ");

  const cancel = async () => {
    setCancelling(true);
    try {
      await api.cancelTask(task.id);
    } catch (error) {
      toast(errorMessage(error), "err");
    } finally {
      setCancelling(false);
    }
  };

  return (
    <article className="run">
      <div className="run-head">
        <button type="button" className="btn-disclosure" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
          <span className="run-tool">{run.tool}</span>
          <code>{short(run.args.artifact, 12)}</code>
          {selector && <span className="muted small">{selector}</span>}
        </button>
        <span className="run-meta">
          <TaskChip state={task.state} />
          <span className="muted small">
            {task.state === "running" ? `running ${fmtDuration(task.started_utc, null)}` : <Time utc={task.finished_utc ?? task.created_utc} relative />}
          </span>
          {task.state === "queued" && (
            <button type="button" className="btn-secondary btn-small" onClick={cancel} disabled={cancelling}>
              Cancel
            </button>
          )}
        </span>
      </div>
      {open && (
        <div className="run-body">
          {!isTerminal(task.state) && (
            <p className="muted" aria-live="polite">
              {task.state === "queued" ? "Waiting in the task queue…" : "The Apprentice is working…"}
            </p>
          )}
          {tracked.error && !isTerminal(task.state) && <p className="muted small">Status check failed: {tracked.error}</p>}
          <TaskOutcome task={task} />
          {hasMore && (
            <div className="form-actions">
              <button type="button" className="btn-secondary btn-small" onClick={() => onNextPage(run)}>
                Next page
              </button>
            </div>
          )}
        </div>
      )}
    </article>
  );
}
