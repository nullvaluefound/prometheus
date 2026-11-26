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
  kind: "create_case" | "ingest" | "tool" | "chat" | "model_test" | "report";
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
  kind: "grant_request"; case: string; id: string; tool: string; artifact: string; audience: "local" | "mcp";
  utc: string; flagged: boolean;
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
    roles: Record<string, string[]>,     // role -> tools
    limits: { max_tool_calls: number, max_excerpt_bytes: number, max_artifact_bytes: number,
              chat_max_turns: number, chat_max_calls_per_turn: number } }
  ```
- `POST api/cases/{id}/grants` with `{ tool, artifact, address?, offset?, limit?, audience, minutes }` returns `Grant`. `minutes` must be 1–60.
- `DELETE api/cases/{id}/grants/{grant}` returns `{ revoked: id }`.
- `GET api/cases/{id}/requests` returns `{ requests: GrantRequest[] }`: pending requests oldest first, then the newest 50 decided.
- `POST api/cases/{id}/requests/{request}/decide` with `{ decision: "approve", minutes }` (1–60) issues a grant for exactly the request's tool, arguments and audience and returns the decided `GrantRequest`. `{ decision: "deny", note? }` (note up to 200 characters) records the denial. A request that is already decided returns 409 `request_already_decided`; a paused case returns 409 `grant_refused`. A closed case can deny but not approve.
- `POST api/cases/{id}/requests` with `{ action: "deny_all", note? }` denies every pending request and returns `{ denied: string[] }`.

### Chat
- `GET api/cases/{id}/chat` returns `{ messages: ChatMessage[], busy: boolean }`.
- `POST api/cases/{id}/chat` with `{ message }` (1–6000 chars) returns `202 {task}` (kind `chat`). The model runs through the broker with the case's role and tool allowlist. Tool calls and intercepted calls appear as `role: "tool"` messages. Earlier assistant text is replayed to the model only while every grant in its `grants` is active for the model's audience; otherwise the model sees a withheld placeholder (docs/SAFETY.md). A call refused for want of an excerpt grant files a `GrantRequest` and its tool row carries `request`. A turn that reaches the turn cap ends with a tool-free `wrapup` answer. Requires `settings.model`. It returns 409 if the model is cloud and `allow_cloud` is false.
- `DELETE api/cases/{id}/chat` clears the conversation and returns `{ cleared: true }`.

### Tasks
- `GET api/tasks?case=<id>` returns `{ tasks: Task[] }`, newest first, at most 100.
- `GET api/tasks/{id}` returns `Task`.
- `POST api/tasks/{id}/cancel` returns `Task`. Only queued tasks can be cancelled; any other state returns 409.

### Models (plug and play)
- `GET api/models` returns `{ models: ModelConfig[] }`.
- `POST api/models` with `{ id, name, provider, base_url, model, api_key? }` returns `ModelConfig`.
- `PUT api/models/{id}` takes the same body. Omitting `api_key` keeps the stored key; `""` clears it. It returns `ModelConfig`.
- `DELETE api/models/{id}` returns `{ deleted: id }`. It returns 409 while a case still selects the model.
- `POST api/models/{id}/test` returns `202 {task}` (kind `model_test`). The result is `{ ok: boolean, detail: string }`.
