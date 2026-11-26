# Forge JSON API

The Forge web app is a React single-page app served at the Forge base path (for example `/prometheus/`). It talks only to this JSON API under `<prefix>api/`. The server-rendered pages `<prefix>login`, `<prefix>setup` and `<prefix>account` remain for sign-in, first-time setup and password changes. Sign-out is a `POST <prefix>logout` form.

## Conventions

- **Auth:** the `prometheus_session` cookie (HttpOnly, SameSite=Strict). An API request without a valid session gets `401 {"error": "sign_in_required"}`; the app then sends the browser to `<prefix>login`.
- **Origin:** every non-GET request must carry `Origin` equal to the Forge origin. Browsers send it on same-origin `fetch` POST/PUT/DELETE.
- **Bodies:**
  - JSON requests use `Content-Type: application/json` and are capped at 64 KiB.
  - Artifact uploads use `application/octet-stream` and are capped at 128 MiB.
- **Errors:** `{"error": "<machine_code>", "message": "<human sentence>"}` with status 400, 401, 403, 404, 409, 413, 429 or 503.
- **Times:** ISO-8601 UTC strings.
- **Untrusted text:** strings that come from samples (strings, symbols, decompilation, YARA/capa names, ledger fields) are untrusted. Render them as text, never as HTML or links.
- **Long work:** anything that runs an Apprentice (Docker) is queued as a task. The endpoint returns `202 {"task": Task}`, and the app polls `GET api/tasks/{id}`. Tasks run one at a time, in order.
- **Live updates:** `GET api/events` is a `text/event-stream` of `change` events whose data is `{ "topics": string[] }`. Topics are `tasks`, `waiting`, `case:<id>`, `chat:<id>`, `requests:<id>` and `investigation:<id>`, or `*` when the stream fell behind. They carry no content: the app re-reads the named data through the API. A stream sends a keepalive comment every 15 seconds and ends after five minutes. A Forge limited to some cases sends no topics for other cases.

## Types

```ts
type CaseStatus = "Ready" | "Paused" | "Closed" | "Pending";

interface CaseRow {
  id: string;                 // [a-z0-9][a-z0-9-]{0,47}
  title: string | null;       // known when created from the Forge
  status: CaseStatus;
  model: string | null;       // model id selected for chat
  allow_cloud: boolean;
  artifacts: number | null;   // from the last ledger read, null if never read
  findings: number | null;
  updated_utc: string | null; // newest audit event
}

interface Artifact {
  sha256: string;
  size: number | null;
  provenance: { source: string; completeness: string; parent: string | null; relation: string; acquired_utc: string }[];
}
interface Finding {
  id: string; kind: string; confidence: string; claim: string; evidence: string[]; artifacts: string[];
  superseded_by?: string | null;
}
interface Grant {
  id: string; tool: string; artifact: string; selector: Record<string, string | number>;
  audience: "local" | "mcp"; expires_utc: string;
}
interface AuditEvent {          // display-safe subset only
  utc: string; decision: string; tool?: string; audience?: string; reason?: string;
  operation?: string; operator?: string; via?: string; artifact?: string; address?: string;
}
interface CaseDetail {
  id: string; title: string | null; status: CaseStatus; image: string; engine: string;
  yara_rules: { sha256: string; rules: number } | null;
  settings: CaseSettings;
  ledger: { title: string; artifacts: Artifact[]; findings: Finding[] } | null; // null when the ledger is unavailable
  grants: Grant[];
  pending_requests: number;   // grant requests waiting on an operator
  waiting: number;            // items for this case on the waiting list
  audit: AuditEvent[];        // newest first, at most 50
}
interface CaseSettings {
  model: string | null;       // ModelConfig.id
  allow_cloud: boolean;       // must be true before a cloud model may see this case
  role: "intake" | "native" | "evidence" | "review";
  tools: string[];            // model tool allowlist; a subset of the role's tools
}

type TaskState = "queued" | "running" | "succeeded" | "failed" | "cancelled";
interface Task {
  id: string;                 // 32 hex
  kind: "create_case" | "ingest" | "tool" | "chat" | "model_test" | "report" | "split" | "review" | "record_finding" |
        "investigate" | "side_question";
  case: string | null;
  title: string;              // human label, e.g. "capa_triage on 3f2a…"
  state: TaskState;
  operator: string;
  created_utc: string; started_utc: string | null; finished_utc: string | null;
  result: unknown | null;     // kind-specific, present when succeeded
  error: string | null;       // fixed, display-safe message when failed
}

interface ModelConfig {
  id: string;                 // [a-z0-9][a-z0-9-]{0,31}
  name: string;
  provider: "ollama" | "openai" | "anthropic";  // openai = any OpenAI-compatible endpoint
  base_url: string;           // e.g. http://10.0.0.20:11434 or https://api.openai.com
  model: string;              // provider model name, e.g. qwen3:32b, gpt-5, claude-opus-5-5
  cloud: boolean;             // derived: anthropic, openai.com, or any non-private host
  has_key: boolean;           // API keys are write-only, never returned
}

interface ChatMessage {
  id: string; role: "user" | "assistant" | "tool";
  text: string;               // assistant/user text; for role "tool" a one-line summary
  tool?: string; decision?: "completed" | "intercepted" | "failed"; reason?: string;
  model?: string; operator?: string; utc: string;
  audience?: "local" | "mcp"; // assistant rows: the audience the text was written for
  grants?: string[];           // assistant rows: grant ids whose excerpts the text may quote
  wrapup?: boolean;            // assistant rows: the tool-free summary written when the turn budget ran out
  request?: string;            // tool rows: the grant request filed for this refused call
}

interface GrantRequest {        // filed by the Forge from a broker denial; only an operator decides it
  id: string; state: "pending" | "approved" | "denied";
  tool: string; artifact: string; selector: Record<string, string | number>; audience: "local" | "mcp";
  created_utc: string;
  reason: string | null;       // model-written, untrusted; never replayed to a model
  flags: string[];             // SHA-256 values and addresses in reason that the case never showed
  decided_by: string | null; decided_utc: string | null;
  grant: string | null;        // the grant id issued on approval
  note: string | null;         // the operator's note on denial
}
interface WaitingItem {
  kind: "grant_request" | "candidate" | "question_proposed" | "question_answer_proposed" | "task_failed" |
        "investigation_waiting" | "investigation_exhausted" | "investigation_failed";
  need?: string | null;                                                            // waiting runs; untrusted
  case: string | null; id: string; utc: string;
  title?: string; error?: string | null;                                           // failed tasks
  tool?: string; artifact?: string; audience?: "local" | "mcp"; flagged?: boolean;  // grant requests
  check?: "passed" | "failed" | "not_assessed" | null; verdict?: string | null;      // candidates
}

// Investigation state. Rows a model wrote carry author "model", audience, grants, session and utc. Treat their text
// as untrusted.
interface Question {
  id: string;                  // Q1, Q2, ...
  state: "proposed" | "open" | "answer_proposed" | "closed" | "withdrawn";
  text: string; outcome: string; artifacts: string[]; parent: string | null;
  created_by: string; created_utc: string; closed_by: string | null; closed_utc: string | null; note: string | null;
}
interface Lead { id: string; state: string; artifact: string; address: string | null; offset: number | null;
                 title: string; question: string | null; }
interface Observation { id: string; kind: "observed" | "inferred"; text: string; artifact: string;
                        lead: string | null; evidence: string[];
                        sources?: ("tool_output" | "sample_content" | "inference")[]; }
interface Candidate {
  id: string; state: "proposed" | "recording" | "recorded" | "rejected";   // recording: a record task holds it
  claim: string; kind: string; confidence: string; artifacts: string[]; evidence: string[];
  limitations: string | null; counterevidence: string | null; question: string | null; lead: string | null;
  observations?: string[];     // observation ids the proposal rests on; their evidence is in evidence
  check: { result: "passed" | "failed" | "not_assessed"; problems: { code: string; ref: string | null }[];
           sources?: ("tool_output" | "sample_content")[];
           grounded?: boolean;   // a tool_output result about its artifacts shows every address in the claim
           utc: string } | null;
  verdicts: { verdict: "supported" | "unsupported" | "insufficient"; rationale: string; model: string;
              utc: string; operator: string }[];
  finding: string | null; decided_by: string | null; decided_utc: string | null; note: string | null;
}
interface InvestigationRun {
  id: string;                  // R1, R2, ...
  state: "queued" | "running" | "paused" | "waiting" | "settling" | "answered" | "exhausted" | "failed" | "cancelled";
  questions: string[];         // the questions it pursues, fixed at start
  budgets: { calls: number; tokens: number; minutes: number };
  spent: { calls: number; tokens: number; active_seconds: number }; active_since: number | null;
  lead_role: "native" | "evidence";
  message: { text: string; by: string; utc: string } | null;  // for the next lead run
  need: { text: string; flags: string[]; author?: "model" } | null;  // why it waits on the operator; untrusted
  summary: { text: string } | null;  // the settle summary; untrusted model text
  current_lead: string | null; steps: number;
  history: { from: string | null; to: string; by: string; utc: string }[];
  started_by: string; created_utc: string; updated_utc: string; error: string | null; acknowledged?: string;
}
interface Investigation { questions: Question[]; leads: Lead[]; observations: Observation[];
                          plan: { items: string[] } | null; candidates: Candidate[];
                          run: InvestigationRun | null; runs: InvestigationRun[]; }
interface EvidenceEntry {        // the exact reply the broker released, under its content SHA-256
  id: string; tool: string; arguments: Record<string, string | number>; excerpt: boolean;
  audience: "local" | "mcp"; grants: string[]; ticket: string; session: string; utc: string; reply: unknown;
}
```

## Endpoints

### Session
- `GET api/me` returns `{ user: string, session_expires_utc: string }`.

### Overview
- `GET api/overview` returns:
  ```
  { cases: CaseRow[], apprentices: {name: string, verified: boolean}[],
    tasks: { queued: number, running: Task | null, recent: Task[] },   // recent: newest 10
    models: number, audit: (AuditEvent & {case: string})[],          // newest 20 across cases
    waiting: { count: number, items: WaitingItem[] } }                 // newest 50 items waiting on an operator
  ```

### Cases
- `GET api/cases` returns `{ cases: CaseRow[] }`.
- `POST api/cases` with `{ id, title }` returns `202 {task}` (kind `create_case`).
- `GET api/cases/{id}` returns `CaseDetail`. Reading the ledger can take a few seconds.
- `POST api/cases/{id}/pause` and `POST api/cases/{id}/resume` return `{ status }`. They are audited with `via=forge` and the operator name.
- `PUT api/cases/{id}/settings` with `CaseSettings` returns `CaseSettings`. It returns 409 if `allow_cloud` is false while a cloud model is selected.
- `POST api/cases/{id}/artifacts?source=<label>&completeness=complete|partial|unknown` with a raw-bytes body returns `202 {task}` (kind `ingest`). The result is `{ sha256, size }`. The label must match `[A-Za-z0-9][A-Za-z0-9 _./(),-]{0,159}`.
- `POST api/cases/{id}/tools/{tool}` with `{ artifact, address?, offset?, limit? }` returns `202 {task}` (kind `tool`). This is an operator inspection, so excerpts are included. The result is the projected tool reply, shaped per tool as in `docs/TOOLS.md`.
- `POST api/cases/{id}/report` returns `202 {task}` (kind `report`). The result is `{ markdown: string }`.
- `GET api/cases/{id}/audit` returns `{ audit: AuditEvent[] }` (newest 200).

### Interception rules and grants
- `GET api/policy` returns:
  ```
  { tools: { name, description, excerpt_only: boolean, paged: boolean, addressed: boolean, timeout_s: number }[],
    denied: string[],                    // tools the broker always refuses, e.g. run_ghidra_script
    state_tools: { name, description, writes: boolean }[],  // case-state tools, dispatched by the broker without a worker
    skills: Record<string, { name, description }[]>,      // role -> skills a chat model may load_skill
    skill_gaps: { name, count, roles: string[], last_utc }[],  // skills models asked for and could not load
    roles: Record<string, string[]>,     // role -> tools
    limits: { max_tool_calls: number, max_excerpt_bytes: number, max_artifact_bytes: number,
              chat_max_turns: number, chat_max_calls_per_turn: number } }
  ```
- `POST api/cases/{id}/grants` with `{ tool, artifact, address?, offset?, limit?, audience, minutes }` returns `Grant`. `minutes` must be 1–60.
- `DELETE api/cases/{id}/grants/{grant}` returns `{ revoked: id }`.
- `GET api/cases/{id}/requests` returns `{ requests: GrantRequest[] }`: pending requests oldest first, then the newest 50 decided.
- `POST api/cases/{id}/requests/{request}/decide` with `{ decision: "approve", minutes }` (1–60) issues a grant for exactly the request's tool, arguments and audience and returns the decided `GrantRequest`. `{ decision: "deny", note? }` (note up to 200 characters) records the denial. A request that is already decided returns 409 `request_already_decided`; a paused case returns 409 `grant_refused`. A closed case can deny but not approve.
- `POST api/cases/{id}/requests` with `{ action: "deny_all", note? }` denies every pending request and returns `{ denied: string[] }`.

### Investigation, evidence and proposed findings
- `GET api/cases/{id}/investigation` returns `Investigation`: everything, for the operator.
- `POST api/cases/{id}/investigation/start` with `{ lead_role?: "native" | "evidence", budgets?: { calls?, tokens?, minutes? } }` starts a run over the usable questions and queues its first step (kind `investigate`). Budgets default to 160 calls, 600000 tokens and 60 active minutes, and must lie within 8-2000, 10000-20000000 and 5-1440. It returns 409 `no_usable_question` without an open question naming an admitted artifact and an outcome, and 409 `investigation_active` while another run is not finished.
- `POST api/cases/{id}/investigation/{pause | resume | cancel | acknowledge}` with `{}` returns the `InvestigationRun`. `resume` works from paused or waiting and queues a step. `acknowledge` takes an exhausted or failed run off the waiting list. A move the run's state does not allow returns 409 `invalid_transition`.
- `POST api/cases/{id}/investigation/message` with `{ text }` (1-1000 characters) leaves a message for the next lead run.
- `POST api/cases/{id}/ask` with `{ question, source: "chat" | "investigation" }` (1-2000 characters) returns `202 {task}` (kind `side_question`). The result is `{ answer, audience, grants }`. The model gets a filtered snapshot and no tools, and nothing is written to the chat or the investigation.
- `PUT api/cases/{id}/links` with `{ cases: string[] }` (up to 8 other cases) returns `202 {task}` (kind `link_cases`). It snapshots each linked case's current recorded findings into the investigation's `inherited` list, which `case_overview` shows read-only.
- `GET api/cases/{id}/outcome` returns the case's outcome card: `{ tools: {tool: {decision: count}}, denials: {reason: count}, grants: {requested, issued, approved, denied}, candidates: {total, passed, failed, not_assessed, proposed, recorded, rejected, reviewed}, questions: {state: count}, leads, observations, tokens: {provider, locality, input, output, sessions}[], model_sessions, first_utc, last_utc }`. It is computed from the audit log and the investigation store, metadata only.
- `GET api/cases/{id}/evidence` returns `{ evidence: {id, tool, artifact, selector, excerpt, audience, utc}[] }`, newest 200. `GET api/cases/{id}/evidence/{sha256}` returns `EvidenceEntry`, or 404 if it is absent or fails its hash check.
- `POST api/cases/{id}/questions` with `{ text, outcome, artifacts }` adds an open question. Text is 1–500 characters, outcome up to 300, and up to 8 artifacts, each admitted to the case (400 `artifact_not_admitted` otherwise). `PUT api/cases/{id}/questions/{qid}` takes the same body and returns 409 `question_closed` for a closed question.
- `POST api/cases/{id}/questions/{qid}/state` with `{ state: "open" | "closed" | "withdrawn", note? }` accepts a proposed question, closes, reopens or withdraws one. Only the operator closes a question.
- `POST api/cases/{id}/questions/{qid}/split` returns `202 {task}` (kind `split`). The case model, with no tools, proposes sub-questions from the question's text; the result is `{ proposed: string[] }` and each waits as `proposed`.
- `POST api/cases/{id}/leads/{lid}/state` with `{ state: "open" | "retired" }`.
- `POST api/cases/{id}/candidates/{cid}/check` re-runs the reference check and returns the `Candidate`.
- `POST api/cases/{id}/candidates/{cid}/review` returns `202 {task}` (kind `review`) for one review session. The result is `{ candidate, verdict }`.
- `POST api/cases/{id}/candidates/{cid}/record` with optional `{ claim, kind, confidence }` edits returns `202 {task}` (kind `record_finding`). It records a ledger finding through the operator `finding` path with the candidate's artifacts and `evidence:<sha256>` locators, and the result is `{ candidate, finding }`.
- `POST api/cases/{id}/candidates/{cid}/reject` with `{ note? }` returns the `Candidate`. A decided candidate, or one a record task holds, returns 409 `candidate_already_decided`. An unreadable investigation store returns 503 `investigation_unreadable`.

### Chat
- `GET api/cases/{id}/chat` returns `{ messages: ChatMessage[], busy: boolean }`.
- `POST api/cases/{id}/chat` with `{ message }` (1–6000 chars) returns `202 {task}` (kind `chat`). The model runs through the broker with the case's role and tool allowlist. Tool calls and intercepted calls appear as `role: "tool"` messages. Earlier assistant text is replayed to the model only while every grant in its `grants` is active for the model's audience; otherwise the model sees a withheld placeholder (docs/SAFETY.md). A call refused for want of an excerpt grant files a `GrantRequest` and its tool row carries `request`. A turn that reaches the turn cap ends with a tool-free `wrapup` answer. Requires `settings.model`. It returns 409 if the model is cloud and `allow_cloud` is false.
- `DELETE api/cases/{id}/chat` clears the conversation and returns `{ cleared: true }`.

### Tasks
- `GET api/tasks?case=<id>` returns `{ tasks: Task[] }`, newest first, at most 100.
- `GET api/tasks/{id}` returns `Task`.
- `POST api/tasks/{id}/cancel` returns `Task`. Only queued tasks can be cancelled; any other state returns 409. A running `investigate` step is the exception: cancelling it cancels its run, which stops at its next broker call.
- `POST api/tasks/{id}/dismiss` takes a failed task off the waiting list and returns `Task`. A failed task stays on the list for 24 hours unless dismissed. Any other state returns 409 `task_not_failed`.

### Lessons
- `GET api/lessons` returns `{ mode: "off" | "shadow" | "inject", modes, lessons: Lesson[] }`, where a `Lesson` is `{ id, state: "proposed" | "adopted" | "retired", cue, action, evidence: {case, candidate}[], created_utc, created_by, adopted }`.
- `PUT api/lessons` with `{ mode }` sets the Forge-wide mode.
- `POST api/lessons/extract` proposes lessons from the visible closed cases' reviewed proposals and returns the lessons with `touched` ids.
- `POST api/lessons/{id}/adopt` with `{ benchmark: { before: {recall, precision}, after: {recall, precision} } }` adopts a proposed lesson. It returns 409 `benchmark_regressed` if the after run lost recall or precision. `POST api/lessons/{id}/retire` with `{}` retires one.

### Models (plug and play)
- `GET api/models` returns `{ models: ModelConfig[] }`.
- `POST api/models` with `{ id, name, provider, base_url, model, api_key? }` returns `ModelConfig`.
- `PUT api/models/{id}` takes the same body. Omitting `api_key` keeps the stored key; `""` clears it. It returns `ModelConfig`.
- `DELETE api/models/{id}` returns `{ deleted: id }`. It returns 409 while a case still selects the model.
- `POST api/models/{id}/test` returns `202 {task}` (kind `model_test`). The result is `{ ok: boolean, detail: string }`.
