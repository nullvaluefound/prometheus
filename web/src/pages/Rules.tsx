import { ROLES, api, type Policy, type PolicyTool } from "../api";
import { Empty, ErrorNote, Loading, Panel, RefreshButton, Time } from "../components/ui";
import { fmtBytes, fmtCount, isRecord, list, txt } from "../format";
import { useDocumentTitle, useResource } from "../hooks";
import { ToolBadges } from "./case/ToolsTab";
import { LessonsPanel } from "./LessonsPanel";

export function RulesPage() {
  useDocumentTitle("Rules");
  const policy = useResource((signal) => api.policy({ signal }), "policy");

  return (
    <>
      <p className="crumb">
        <a href="#/">Forge</a> / Rules
      </p>
      <div className="page-head">
        <h1>Rules</h1>
        <div className="page-actions">
          <RefreshButton onClick={policy.reload} busy={policy.loading && Boolean(policy.data)} />
        </div>
      </div>
      <section className="panel explainer" aria-label="How interception works">
        <p>
          Every model tool call passes through the case broker. The broker checks the call against this closed tool contract and the case's
          role and tool allowlist, and writes an audit event <strong>before</strong> anything is dispatched to an Apprentice. Calls outside the
          contract are intercepted and recorded with their reason.
        </p>
        <p>
          Excerpt-only tools return sample text such as decompilation or import names. The broker withholds that output unless the operator
          holds an active grant for the exact case, artifact, tool, selector and audience. Grants are per case: create and revoke them on each
          case's Rules &amp; grants tab.
        </p>
      </section>
      {policy.error && <ErrorNote message={policy.error} onRetry={policy.reload} />}
      {!policy.data && !policy.error && <Loading label="Loading the interception policy…" />}
      {policy.data && <PolicyBody policy={policy.data} />}
    </>
  );
}

function PolicyBody({ policy }: { policy: Policy }) {
  const tools = list<PolicyTool>(policy.tools).filter((tool) => isRecord(tool) && typeof tool.name === "string");
  const denied = list<string>(policy.denied).filter((name) => typeof name === "string");
  const roles = isRecord(policy.roles) ? policy.roles : {};
  const roleNames = [...ROLES.filter((name) => name in roles), ...Object.keys(roles).filter((name) => !(ROLES as readonly string[]).includes(name))];
  const matrixTools = [...tools.map((tool) => tool.name)];
  for (const name of roleNames) {
    for (const tool of list<string>(roles[name])) if (typeof tool === "string" && !matrixTools.includes(tool)) matrixTools.push(tool);
  }
  const limits = isRecord(policy.limits) ? policy.limits : null;

  return (
    <div className="stack">
      <Panel title="Tools">
        {tools.length === 0 ? (
          <Empty>No tools are exposed.</Empty>
        ) : (
          <ul className="tool-list">
            {tools.map((tool) => (
              <li key={tool.name}>
                <div className="tool-list-head">
                  <code className="tool-name">{tool.name}</code>
                  <ToolBadges tool={tool} />
                </div>
                <p>{txt(tool.description)}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="columns">
        <Panel title="Denied tools">
          {denied.length === 0 ? (
            <Empty>No tools are on the deny list.</Empty>
          ) : (
            <>
              <ul className="chip-list">
                {denied.map((name) => (
                  <li key={name}>
                    <span className="chip chip-err chip-nodot">
                      <code>{name}</code>
                    </span>
                  </li>
                ))}
              </ul>
              <p className="muted small">The broker always refuses these, whatever the role, allowlist or grant.</p>
            </>
          )}
        </Panel>

        <Panel title="Limits">
          {limits ? (
            <dl className="kv">
              <div>
                <dt>Tool calls per session</dt>
                <dd>{fmtCount(limits.max_tool_calls)}</dd>
              </div>
              <div>
                <dt>Excerpt size</dt>
                <dd>{fmtBytes(limits.max_excerpt_bytes)}</dd>
              </div>
              <div>
                <dt>Artifact size</dt>
                <dd>{fmtBytes(limits.max_artifact_bytes)}</dd>
              </div>
              <div>
                <dt>Chat turns per message</dt>
                <dd>{fmtCount(limits.chat_max_turns)}</dd>
              </div>
              <div>
                <dt>Tool calls per chat turn</dt>
                <dd>{fmtCount(limits.chat_max_calls_per_turn)}</dd>
              </div>
            </dl>
          ) : (
            <Empty>No limits reported.</Empty>
          )}
        </Panel>
      </div>

      <Panel title="Roles and tools">
        {roleNames.length === 0 ? (
          <Empty>No roles are defined.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="data matrix">
              <caption className="sr-only">Which tools each model role may call</caption>
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  {roleNames.map((name) => (
                    <th scope="col" key={name} className="center">
                      {name}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {matrixTools.map((tool) => (
                  <tr key={tool}>
                    <th scope="row">
                      <code>{tool}</code>
                    </th>
                    {roleNames.map((name) => {
                      const allowed = list<string>(roles[name]).includes(tool);
                      return (
                        <td key={name} className={`center ${allowed ? "yes" : "no"}`}>
                          {allowed ? (
                            <>
                              <span aria-hidden="true">●</span>
                              <span className="sr-only">allowed</span>
                            </>
                          ) : (
                            <>
                              <span aria-hidden="true">·</span>
                              <span className="sr-only">not allowed</span>
                            </>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="muted small">A case's tool allowlist can narrow its role's tools but never widen them.</p>
      </Panel>

      <SkillsPanel policy={policy} roleNames={roleNames} />
      <LessonsPanel />
    </div>
  );
}

function SkillsPanel({ policy, roleNames }: { policy: Policy; roleNames: string[] }) {
  const skills = isRecord(policy.skills) ? policy.skills : {};
  const gaps = list<NonNullable<Policy["skill_gaps"]>[number]>(policy.skill_gaps).filter(isRecord);
  return (
    <div className="columns">
      <Panel title="Skills by role">
        <p className="muted small">
          A chat model sees each skill's name and description and loads a body with <code>load_skill</code> when it needs the procedure. Skills are
          git-reviewed files. They never change tools, grants or policy.
        </p>
        <ul className="rows">
          {roleNames.map((role) => (
            <li key={role}>
              <span>{role}</span>
              <span>
                {list<{ name: string }>(skills[role]).length === 0 ? (
                  <span className="muted">none</span>
                ) : (
                  list<{ name: string }>(skills[role]).map((skill) => (
                    <code key={txt(skill.name)} className="spaced">
                      {txt(skill.name)}
                    </code>
                  ))
                )}
              </span>
            </li>
          ))}
        </ul>
      </Panel>
      <Panel title="Skill gaps">
        {gaps.length === 0 ? (
          <Empty>No model has asked for a skill it could not load.</Empty>
        ) : (
          <>
            <p className="muted small">Skills models asked for and could not load. The names are model-chosen. Consider writing the procedure they point to.</p>
            <ul className="rows">
              {gaps.map((gap) => (
                <li key={txt(gap.name)}>
                  <code>{txt(gap.name)}</code>
                  <span className="muted small">
                    {fmtCount(gap.count)} asks · {list(gap.roles).map(txt).join(", ")} · <Time utc={gap.last_utc} relative />
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Panel>
    </div>
  );
}
