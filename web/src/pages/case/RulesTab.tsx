import { useMemo, useState, type FormEvent } from "react";
import {
  AUDIENCES,
  ROLES,
  api,
  type Artifact,
  type Audience,
  type CaseSettings,
  type Grant,
  type ModelConfig,
  type Policy,
  type Role,
} from "../../api";
import { useToast } from "../../components/toast";
import { Badge, ConfirmButton, Empty, ErrorNote, Loading, Note, Panel, Time } from "../../components/ui";
import { DIGEST, LIMIT_DEFAULT, isRecord, list, short, txt } from "../../format";
import { errorMessage, useResource, type Resource } from "../../hooks";
import type { CaseContext } from "../CaseView";
import { ArtifactPicker, SelectorFields, ToolBadges, chosenArtifact, parseSelector, usableTools } from "./ToolsTab";
import { RequestsPanel } from "./RequestsPanel";

export function RulesTab({ ctx, policy }: { ctx: CaseContext; policy: Resource<Policy> }) {
  const settings = ctx.detail.settings;
  return (
    <div className="stack">
      <RequestsPanel ctx={ctx} />
      <SettingsPanel key={JSON.stringify(settings ?? null)} ctx={ctx} policy={policy} />
      <GrantsPanel ctx={ctx} />
      <NewGrantPanel ctx={ctx} policy={policy} />
    </div>
  );
}

function minutesLeft(utc: string): string {
  const time = new Date(utc).getTime();
  if (Number.isNaN(time)) return "";
  const minutes = Math.round((time - Date.now()) / 60000);
  return minutes <= 0 ? "expiring" : `${minutes} min left`;
}

function GrantsPanel({ ctx }: { ctx: CaseContext }) {
  const toast = useToast();
  const grants = list<Grant>(ctx.detail.grants).filter(isRecord);

  const revoke = async (grant: Grant) => {
    try {
      await api.revokeGrant(ctx.id, grant.id);
      toast(`Grant ${short(grant.id, 8)} revoked.`, "ok");
      ctx.reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <Panel title="Active excerpt grants">
      {grants.length === 0 ? (
        <Empty>No active grants. Models receive no excerpts from this case.</Empty>
      ) : (
        <div className="table-wrap">
          <table className="data wide">
            <thead>
              <tr>
                <th scope="col">Grant</th>
                <th scope="col">Tool</th>
                <th scope="col">Artifact</th>
                <th scope="col">Selector</th>
                <th scope="col">Audience</th>
                <th scope="col">Expires</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {grants.map((grant) => {
                const selector = isRecord(grant.selector)
                  ? Object.entries(grant.selector)
                      .filter(([key]) => key !== "artifact")
                      .map(([key, value]) => `${key}=${txt(value)}`)
                      .join(" ")
                  : "";
                return (
                  <tr key={txt(grant.id)}>
                    <td>
                      <code title={txt(grant.id)}>{short(grant.id, 8)}</code>
                    </td>
                    <td>
                      <code>{txt(grant.tool)}</code>
                    </td>
                    <td>
                      <code title={txt(grant.artifact)}>{short(grant.artifact, 16)}</code>
                    </td>
                    <td>{selector ? <code>{selector}</code> : <span className="muted">whole tool call</span>}</td>
                    <td>{txt(grant.audience)}</td>
                    <td className="nowrap">
                      <Time utc={grant.expires_utc} />
                      <span className="muted small block">{minutesLeft(txt(grant.expires_utc))}</span>
                    </td>
                    <td>
                      <ConfirmButton label="Revoke" prompt="Revoke this grant?" confirmLabel="Revoke" onConfirm={() => revoke(grant)} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small">Revoking stops future releases. It cannot recall an excerpt already delivered.</p>
    </Panel>
  );
}

function NewGrantPanel({ ctx, policy }: { ctx: CaseContext; policy: Resource<Policy> }) {
  const toast = useToast();
  const artifacts = useMemo(
    () => list<Artifact>(ctx.detail.ledger?.artifacts).filter((item) => isRecord(item) && DIGEST.test(txt(item.sha256))),
    [ctx.detail.ledger],
  );
  const tools = usableTools(policy.data).filter((tool) => tool.name !== "artifact_summary");
  const [toolName, setToolName] = useState("");
  const [artifact, setArtifact] = useState(artifacts[0]?.sha256 ?? "");
  const [address, setAddress] = useState("");
  const [offset, setOffset] = useState("0");
  const [limit, setLimit] = useState(String(LIMIT_DEFAULT));
  const [audience, setAudience] = useState<Audience>("local");
  const [minutes, setMinutes] = useState("10");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const tool = tools.find((item) => item.name === toolName) ?? tools[0];
  const chosen = chosenArtifact(artifacts, artifact);
  const disabled = ctx.inactive !== null;

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
    const span = Number(minutes);
    if (!Number.isInteger(span) || span < 1 || span > 60) {
      setError("Minutes must be a whole number from 1 to 60.");
      return;
    }
    setSubmitting(true);
    try {
      const grant = await api.createGrant(ctx.id, { tool: tool.name, artifact: digest, ...parsed.args, audience, minutes: span });
      toast(`Grant ${short(grant.id, 8)} active for ${span} min.`, "ok");
      ctx.reload();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Panel title="New grant">
      <p className="muted small">
        A grant releases one exact tool call's excerpt (case, artifact, tool, selector and audience) until it expires. Without one, the broker
        withholds excerpts from models.
      </p>
      {policy.error && !policy.data && <ErrorNote message={policy.error} onRetry={policy.reload} />}
      {!policy.data && !policy.error && <Loading label="Loading the tool policy…" />}
      {disabled && <Note tone="warn">{ctx.inactive} Grants are refused until then.</Note>}
      {policy.data && (
        <form className="stack-sm" onSubmit={submit} noValidate>
          {error && (
            <p className="note note-err" role="alert">
              {error}
            </p>
          )}
          <div className="form-grid">
            <label className="field">
              <span>Tool</span>
              <select className="mono" name="tool" value={tool?.name ?? ""} onChange={(event) => setToolName(event.target.value)} disabled={disabled}>
                {tools.map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <ArtifactPicker artifacts={artifacts} value={chosen} onChange={setArtifact} disabled={disabled} />
            <SelectorFields
              tool={tool}
              address={address}
              offset={offset}
              limit={limit}
              setAddress={setAddress}
              setOffset={setOffset}
              setLimit={setLimit}
              disabled={disabled}
            />
            <label className="field">
              <span>Audience</span>
              <select name="audience" value={audience} onChange={(event) => setAudience(event.target.value as Audience)} disabled={disabled}>
                {AUDIENCES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Minutes</span>
              <input
                type="number"
                name="minutes"
                inputMode="numeric"
                min={1}
                max={60}
                step={1}
                value={minutes}
                onChange={(event) => setMinutes(event.target.value)}
                required
                disabled={disabled}
              />
            </label>
          </div>
          {tool && <ToolBadges tool={tool} />}
          <p className="muted small">
            <strong>local</strong> applies to the built-in model runner. <strong>mcp</strong> applies to clients on the case's MCP broker and can
            disclose evidence to a hosted model. Released excerpts can contain sample instructions or secrets.
          </p>
          <div className="form-actions">
            <button type="submit" disabled={submitting || !tool || disabled}>
              {submitting ? "Granting…" : "Create grant"}
            </button>
          </div>
        </form>
      )}
    </Panel>
  );
}

function SettingsPanel({ ctx, policy }: { ctx: CaseContext; policy: Resource<Policy> }) {
  const toast = useToast();
  const initial: CaseSettings = ctx.detail.settings ?? { model: null, allow_cloud: false, role: "native", tools: [] };
  const models = useResource((signal) => api.models({ signal }), "models");
  const [model, setModel] = useState(initial.model ?? "");
  const [allowCloud, setAllowCloud] = useState(Boolean(initial.allow_cloud));
  const [role, setRole] = useState<Role>(ROLES.includes(initial.role) ? initial.role : "native");
  const [tools, setTools] = useState<Set<string>>(() => new Set(list<string>(initial.tools)));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const roles = policy.data && isRecord(policy.data.roles) ? policy.data.roles : null;
  const roleNames = roles ? ROLES.filter((name) => Array.isArray(roles[name])) : ROLES;
  const roleTools = roles ? list<string>(roles[role]) : [];
  const toolInfo = new Map(usableTools(policy.data).map((tool) => [tool.name, tool]));
  const modelList = list<ModelConfig>(models.data?.models);
  const selected = modelList.find((item) => item.id === model);
  const conflict = Boolean(selected?.cloud) && !allowCloud;
  const closed = ctx.detail.status === "Closed";
  const missingModel = model !== "" && models.data !== undefined && !selected;

  const changeRole = (next: Role) => {
    setRole(next);
    const allowed = new Set(roles ? list<string>(roles[next]) : []);
    setTools((current) => new Set([...current].filter((name) => allowed.has(name))));
  };

  const toggle = (name: string, on: boolean) =>
    setTools((current) => {
      const next = new Set(current);
      if (on) next.add(name);
      else next.delete(name);
      return next;
    });

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (conflict) {
      setError("Allow cloud models for this case, or pick a local model.");
      return;
    }
    setSaving(true);
    try {
      const body: CaseSettings = {
        model: model || null,
        allow_cloud: allowCloud,
        role,
        tools: roleTools.filter((name) => tools.has(name)),
      };
      await api.saveSettings(ctx.id, body);
      toast("Model settings saved.", "ok");
      ctx.reload();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel title="Model settings" id="model-settings">
      {(policy.error && !policy.data) || models.error ? (
        <ErrorNote
          message={policy.error ?? models.error ?? ""}
          onRetry={() => {
            policy.reload();
            models.reload();
          }}
        />
      ) : null}
      {(!policy.data || !models.data) && !policy.error && !models.error && <Loading label="Loading models and roles…" />}
      {policy.data && models.data && (
        <form className="stack-sm" onSubmit={save} noValidate>
          {error && (
            <p className="note note-err" role="alert">
              {error}
            </p>
          )}
          <div className="form-grid">
            <label className="field">
              <span>Chat model</span>
              <select name="model" value={model} onChange={(event) => setModel(event.target.value)} disabled={closed}>
                <option value="">No model</option>
                {missingModel && <option value={model}>{model} (not configured)</option>}
                {modelList.map((item) => (
                  <option key={item.id} value={item.id}>
                    {txt(item.name) || item.id} · {item.provider}
                    {item.cloud ? " · cloud" : " · local"}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Role</span>
              <select name="role" value={role} onChange={(event) => changeRole(event.target.value as Role)} disabled={closed}>
                {roleNames.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {modelList.length === 0 && (
            <p className="muted small">
              No models are configured. <a href="#/models">Add one on the Models page</a>.
            </p>
          )}

          <div className={`cloud-toggle${allowCloud || selected?.cloud ? " cloud-toggle-on" : ""}`}>
            <label className="check">
              <input type="checkbox" checked={allowCloud} onChange={(event) => setAllowCloud(event.target.checked)} disabled={closed} />
              <span>Allow cloud models for this case</span>
            </label>
            <p className="small">
              A cloud provider will receive projected evidence from this case: your messages, tool results and any granted excerpts. Check the
              case's data classification before you allow it.
            </p>
          </div>
          {conflict && (
            <Note tone="err">The selected model is a cloud model. Allow cloud models for this case, or pick a local model, before saving.</Note>
          )}

          <fieldset>
            <legend>Tools the model may call</legend>
            {roleTools.length === 0 ? (
              <p className="muted small">The {role} role has no tools.</p>
            ) : (
              <>
                <div className="check-grid">
                  {roleTools.map((name) => {
                    const info = toolInfo.get(name);
                    return (
                      <label className="check" key={name}>
                        <input type="checkbox" checked={tools.has(name)} onChange={(event) => toggle(name, event.target.checked)} disabled={closed} />
                        <span>
                          <code>{name}</code>
                          {info?.excerpt_only && (
                            <>
                              {" "}
                              <Badge tone="warn">grant</Badge>
                            </>
                          )}
                        </span>
                      </label>
                    );
                  })}
                </div>
                <div className="form-actions">
                  <button type="button" className="btn-secondary btn-small" onClick={() => setTools(new Set(roleTools))} disabled={closed}>
                    Select all
                  </button>
                  <button type="button" className="btn-secondary btn-small" onClick={() => setTools(new Set())} disabled={closed}>
                    Select none
                  </button>
                  <span className="muted small">
                    {roleTools.filter((name) => tools.has(name)).length} of {roleTools.length} {role} tools allowed.
                  </span>
                </div>
              </>
            )}
          </fieldset>
          <div className="form-actions">
            <button type="submit" disabled={saving || conflict || closed}>
              {saving ? "Saving…" : "Save settings"}
            </button>
          </div>
        </form>
      )}
    </Panel>
  );
}
