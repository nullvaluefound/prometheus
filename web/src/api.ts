// Typed client for the Forge JSON API in docs/FORGE_API.md. Every path is relative to the base path.
// Values in these types can carry untrusted sample text. Render them only as React text children.

export type CaseStatus = "Ready" | "Paused" | "Closed" | "Pending";
export type Role = "intake" | "native" | "evidence" | "review";
export type Audience = "local" | "mcp";
export type Completeness = "complete" | "partial" | "unknown";
export type Provider = "ollama" | "openai" | "anthropic";
export type TaskState = "queued" | "running" | "succeeded" | "failed" | "cancelled";
export type TaskKind =
  | "create_case"
  | "ingest"
  | "tool"
  | "chat"
  | "model_test"
  | "report"
  | "split"
  | "review"
  | "record_finding";

export const ROLES: readonly Role[] = ["intake", "native", "evidence", "review"];
export const AUDIENCES: readonly Audience[] = ["local", "mcp"];
export const COMPLETENESS: readonly Completeness[] = ["complete", "partial", "unknown"];
export const PROVIDERS: readonly Provider[] = ["ollama", "openai", "anthropic"];

export interface CaseRow {
  id: string;
  title: string | null;
  status: CaseStatus;
  model: string | null;
  allow_cloud: boolean;
  artifacts: number | null;
  findings: number | null;
  updated_utc: string | null;
}

export interface Provenance {
  source: string;
  completeness: string;
  parent: string | null;
  relation: string;
  acquired_utc: string;
}

export interface Artifact {
  sha256: string;
  size: number | null;
  provenance: Provenance[];
}

export interface Finding {
  id: string;
  kind: string;
  confidence: string;
  claim: string;
  evidence: string[];
  artifacts: string[];
  superseded_by?: string | null;
}

export interface Grant {
  id: string;
  tool: string;
  artifact: string;
  selector: Record<string, string | number>;
  audience: Audience;
  expires_utc: string;
}

export interface AuditEvent {
  utc: string;
  decision: string;
  tool?: string;
  audience?: string;
  reason?: string;
  operation?: string;
  operator?: string;
  via?: string;
  artifact?: string;
  address?: string;
}

export type CaseAuditEvent = AuditEvent & { case: string };

export interface CaseSettings {
  model: string | null;
  allow_cloud: boolean;
  role: Role;
  tools: string[];
}

export interface Ledger {
  title: string;
  artifacts: Artifact[];
  findings: Finding[];
}

export interface CaseDetail {
  id: string;
  title: string | null;
  status: CaseStatus;
  image: string;
  engine: string;
  yara_rules: { sha256: string; rules: number } | null;
  settings: CaseSettings;
  ledger: Ledger | null;
  grants: Grant[];
  pending_requests?: number;
  waiting?: number;
  audit: AuditEvent[];
}

export interface Task {
  id: string;
  kind: TaskKind;
  case: string | null;
  title: string;
  state: TaskState;
  operator: string;
  created_utc: string;
  started_utc: string | null;
  finished_utc: string | null;
  result: unknown | null;
  error: string | null;
}

export interface ModelConfig {
  id: string;
  name: string;
  provider: Provider;
  base_url: string;
  model: string;
  cloud: boolean;
  has_key: boolean;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "tool";
  text: string;
  tool?: string;
  decision?: "completed" | "intercepted" | "failed";
  reason?: string;
  model?: string;
  operator?: string;
  utc: string;
  audience?: "local" | "mcp"; // assistant rows: the audience the text was written for
  grants?: string[]; // assistant rows: excerpt grants the text may quote
  wrapup?: boolean; // assistant rows: the tool-free summary written when the turn budget ran out
  request?: string; // tool rows: the grant request filed for this refused call
}

export type RequestState = "pending" | "approved" | "denied";

export interface GrantRequest {
  id: string;
  state: RequestState;
  tool: string;
  artifact: string;
  selector: Record<string, string | number>;
  audience: Audience;
  created_utc: string;
  reason: string | null; // model-written, untrusted
  flags: string[]; // SHA-256 values and addresses in the reason that the case never showed
  decided_by: string | null;
  decided_utc: string | null;
  grant: string | null;
  note: string | null; // operator-written
}

export interface WaitingItem {
  kind:
    | "grant_request"
    | "candidate"
    | "question_proposed"
    | "question_answer_proposed"
    | "task_failed"
    | "investigation_waiting"
    | "investigation_exhausted"
    | "investigation_failed";
  need?: string | null;
  case: string | null;
  title?: string;
  error?: string | null;
  id: string;
  tool?: string;
  artifact?: string;
  audience?: Audience;
  utc: string;
  flagged?: boolean;
  check?: CheckResult | null;
  verdict?: Verdict | null;
}

/** Model-written rows carry who wrote them; operator rows do not. */
export interface Authored {
  author?: "model";
  session?: string;
  audience?: Audience;
  grants?: string[];
  utc?: string;
}

export type QuestionState = "proposed" | "open" | "answer_proposed" | "closed" | "withdrawn";

export interface Question extends Authored {
  id: string;
  state: QuestionState;
  text: string;
  outcome: string;
  artifacts: string[];
  parent: string | null;
  created_by: string;
  created_utc: string;
  closed_by: string | null;
  closed_utc: string | null;
  note: string | null;
}

export interface Lead extends Authored {
  id: string;
  state: "open" | "claimed" | "done" | "retired" | "stopped";
  artifact: string;
  address: string | null;
  offset: number | null;
  title: string;
  question: string | null;
  summary?: ({ text: string; run?: string } & Authored) | null;
}

export interface Observation extends Authored {
  id: string;
  kind: "observed" | "inferred";
  text: string;
  artifact: string;
  lead: string | null;
  evidence: string[];
}

export type CheckResult = "passed" | "failed" | "not_assessed";
export type Verdict = "supported" | "unsupported" | "insufficient";

export interface CandidateCheck {
  result: CheckResult;
  problems: { code: string; ref: string | null }[];
  utc: string;
}

export interface Candidate extends Authored {
  id: string;
  state: "proposed" | "recording" | "recorded" | "rejected";
  claim: string;
  kind: string;
  confidence: string;
  artifacts: string[];
  evidence: string[];
  limitations: string | null;
  counterevidence: string | null;
  question: string | null;
  lead: string | null;
  check: CandidateCheck | null;
  verdicts: { verdict: Verdict; rationale: string; model: string; utc: string; operator: string }[];
  finding: string | null;
  decided_by: string | null;
  decided_utc: string | null;
  note: string | null;
}

export type RunState = "queued" | "running" | "paused" | "waiting" | "settling" | "answered" | "exhausted" | "failed" | "cancelled";

export interface InvestigationRun {
  id: string;
  state: RunState;
  questions: string[];
  budgets: { calls: number; tokens: number; minutes: number };
  spent: { calls: number; tokens: number; active_seconds: number };
  active_since: number | null;
  lead_role: "native" | "evidence";
  message: { text: string; by: string; utc: string } | null;
  need: ({ text: string; flags: string[] } & Authored) | null;
  summary: ({ text: string } & Authored) | null;
  current_lead: string | null;
  steps: number;
  history: { from: RunState | null; to: RunState; by: string; utc: string }[];
  started_by: string;
  created_utc: string;
  updated_utc: string;
  error: string | null;
  acknowledged?: string;
}

export interface Investigation {
  questions: Question[];
  leads: Lead[];
  observations: Observation[];
  plan: ({ items: string[] } & Authored) | null;
  candidates: Candidate[];
  run?: InvestigationRun | null;
  runs?: InvestigationRun[];
  links?: { case: string; linked_by: string; refreshed_utc: string }[];
  inherited?: { case: string; finding: string; kind: string; confidence: string; claim: string; artifacts: string[] }[];
}

export interface Lesson {
  id: string;
  state: "proposed" | "adopted" | "retired";
  cue: string;
  action: string;
  evidence: { case: string; candidate: string }[];
  created_utc: string;
  created_by: string;
  adopted: { by: string; utc: string; benchmark: unknown } | null;
}

export interface LessonsState {
  mode: "off" | "shadow" | "inject";
  modes: string[];
  lessons: Lesson[];
}

export interface EvidenceRow {
  id: string;
  tool: string;
  artifact: string;
  selector: Record<string, string | number>;
  excerpt: boolean;
  audience: Audience;
  utc: string;
}

export interface EvidenceEntry {
  id: string;
  tool: string;
  arguments: Record<string, string | number>;
  excerpt: boolean;
  audience: Audience;
  grants: string[];
  ticket: string;
  session: string;
  utc: string;
  reply: unknown;
}

export interface Outcome {
  tools: Record<string, Partial<Record<string, number>>>;
  denials: Record<string, number>;
  grants: { requested: number; issued: number; approved: number; denied: number };
  candidates: { total: number; passed: number; failed: number; not_assessed: number; proposed: number; recorded: number; rejected: number; reviewed: number };
  questions: Record<string, number>;
  leads: number;
  observations: number;
  tokens: { provider: string; locality: "local" | "cloud"; input: number; output: number; sessions: number }[];
  model_sessions: number;
  first_utc: string | null;
  last_utc: string | null;
}

export interface QuestionInput {
  text: string;
  outcome: string;
  artifacts: string[];
}

export interface RecordInput {
  claim?: string;
  kind?: string;
  confidence?: string;
}

export interface DecideInput {
  decision: "approve" | "deny";
  minutes?: number;
  note?: string;
}

export interface Me {
  user: string;
  session_expires_utc: string;
}

export interface Apprentice {
  name: string;
  verified: boolean;
}

export interface Overview {
  cases: CaseRow[];
  apprentices: Apprentice[];
  tasks: { queued: number; running: Task | null; recent: Task[] };
  models: number;
  audit: CaseAuditEvent[];
  waiting?: { count: number; items: WaitingItem[] };
}

export interface PolicyTool {
  name: string;
  description: string;
  excerpt_only: boolean;
  paged: boolean;
  addressed: boolean;
  timeout_s: number;
}

export interface PolicyLimits {
  max_tool_calls: number;
  max_excerpt_bytes: number;
  max_artifact_bytes: number;
  chat_max_turns: number;
  chat_max_calls_per_turn: number;
}

export interface Policy {
  tools: PolicyTool[];
  state_tools?: { name: string; description: string; writes: boolean }[];
  skills?: Record<string, { name: string; description: string }[]>;
  skill_gaps?: { name: string; count: number; roles: string[]; last_utc: string }[];
  denied: string[];
  roles: Record<string, string[]>;
  limits: PolicyLimits;
}

export interface ChatState {
  messages: ChatMessage[];
  busy: boolean;
}

export interface TaskEnvelope {
  task: Task;
}

export interface ToolArgs {
  artifact: string;
  address?: string;
  offset?: number;
  limit?: number;
}

export interface GrantInput extends ToolArgs {
  tool: string;
  audience: Audience;
  minutes: number;
}

export interface ModelInput {
  id: string;
  name: string;
  provider: Provider;
  base_url: string;
  model: string;
  api_key?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

const FALLBACK: Record<number, string> = {
  400: "The Forge did not accept this request.",
  401: "Sign in to continue.",
  403: "The Forge refused this request.",
  404: "Not found.",
  409: "This conflicts with the current state. Refresh and try again.",
  413: "The request body is larger than the Forge accepts.",
  429: "Too many requests. Wait a moment and try again.",
  503: "The case service is unavailable. Try again shortly.",
};

function fallbackMessage(status: number): string {
  return FALLBACK[status] ?? (status >= 500 ? "The Forge hit a server error." : `The request failed (HTTP ${status}).`);
}

function field(data: unknown, key: string): string | null {
  if (typeof data !== "object" || data === null) return null;
  const value = (data as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

interface RequestOptions {
  json?: unknown;
  blob?: Blob;
  signal?: AbortSignal;
}

let redirecting = false;

async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: BodyInit | undefined;
  if (options.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.json);
  } else if (options.blob !== undefined) {
    headers["Content-Type"] = "application/octet-stream";
    body = options.blob;
  }
  let response: Response;
  try {
    response = await fetch("api/" + path, {
      method,
      headers,
      body,
      credentials: "same-origin",
      cache: "no-store",
      signal: options.signal,
    });
  } catch (error) {
    if (isAbortError(error)) throw error;
    throw new ApiError(0, "network", "The Forge could not be reached. Check the connection and try again.");
  }
  if (response.status === 401) {
    if (!redirecting) {
      redirecting = true;
      window.location.href = "login";
    }
    throw new ApiError(401, "sign_in_required", FALLBACK[401]);
  }
  const text = await response.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!response.ok) {
    const message = field(data, "message") ?? fallbackMessage(response.status);
    throw new ApiError(response.status, field(data, "error") ?? `http_${response.status}`, message.slice(0, 500));
  }
  if (data === null) throw new ApiError(response.status, "invalid_response", "The Forge sent an unreadable response.");
  return data as T;
}

type Opts = { signal?: AbortSignal };
const seg = encodeURIComponent;
const get = <T>(path: string, opts?: Opts) => request<T>("GET", path, { signal: opts?.signal });
const post = <T>(path: string, json?: unknown) => request<T>("POST", path, { json });
const put = <T>(path: string, json: unknown) => request<T>("PUT", path, { json });
const del = <T>(path: string) => request<T>("DELETE", path);

export const api = {
  me: (opts?: Opts) => get<Me>("me", opts),
  overview: (opts?: Opts) => get<Overview>("overview", opts),

  cases: (opts?: Opts) => get<{ cases: CaseRow[] }>("cases", opts),
  createCase: (id: string, title: string) => post<TaskEnvelope>("cases", { id, title }),
  caseDetail: (id: string, opts?: Opts) => get<CaseDetail>(`cases/${seg(id)}`, opts),
  pauseCase: (id: string) => post<{ status: CaseStatus }>(`cases/${seg(id)}/pause`),
  resumeCase: (id: string) => post<{ status: CaseStatus }>(`cases/${seg(id)}/resume`),
  saveSettings: (id: string, settings: CaseSettings) => put<CaseSettings>(`cases/${seg(id)}/settings`, settings),
  uploadArtifact: (id: string, file: Blob, source: string, completeness: Completeness) =>
    request<TaskEnvelope>("POST", `cases/${seg(id)}/artifacts?${new URLSearchParams({ source, completeness })}`, {
      blob: file,
    }),
  runTool: (id: string, tool: string, args: ToolArgs) => post<TaskEnvelope>(`cases/${seg(id)}/tools/${seg(tool)}`, args),
  report: (id: string) => post<TaskEnvelope>(`cases/${seg(id)}/report`),
  audit: (id: string, opts?: Opts) => get<{ audit: AuditEvent[] }>(`cases/${seg(id)}/audit`, opts),

  policy: (opts?: Opts) => get<Policy>("policy", opts),
  createGrant: (id: string, grant: GrantInput) => post<Grant>(`cases/${seg(id)}/grants`, grant),
  revokeGrant: (id: string, grant: string) => del<{ revoked: string }>(`cases/${seg(id)}/grants/${seg(grant)}`),
  investigation: (id: string, opts?: Opts) => get<Investigation>(`cases/${seg(id)}/investigation`, opts),
  outcome: (id: string, opts?: Opts) => get<Outcome>(`cases/${seg(id)}/outcome`, opts),
  ask: (id: string, question: string, source: "chat" | "investigation") =>
    post<TaskEnvelope>(`cases/${seg(id)}/ask`, { question, source }),
  setLinks: (id: string, cases: string[]) => put<TaskEnvelope>(`cases/${seg(id)}/links`, { cases }),
  lessons: (opts?: Opts) => get<LessonsState>("lessons", opts),
  setLessonsMode: (mode: string) => put<LessonsState>("lessons", { mode }),
  extractLessons: () => post<LessonsState>("lessons/extract"),
  changeLesson: (id: string, action: "adopt" | "retire", body: unknown) => post<Lesson>(`lessons/${seg(id)}/${action}`, body),
  startInvestigation: (id: string, input: { lead_role: string; budgets: { calls: number; tokens: number; minutes: number } }) =>
    post<InvestigationRun>(`cases/${seg(id)}/investigation/start`, input),
  investigationAction: (id: string, action: "pause" | "resume" | "cancel" | "acknowledge" | "message", text?: string) =>
    post<InvestigationRun>(`cases/${seg(id)}/investigation/${action}`, text === undefined ? {} : { text }),
  evidence: (id: string, opts?: Opts) => get<{ evidence: EvidenceRow[] }>(`cases/${seg(id)}/evidence`, opts),
  evidenceEntry: (id: string, evidence: string, opts?: Opts) =>
    get<EvidenceEntry>(`cases/${seg(id)}/evidence/${seg(evidence)}`, opts),
  addQuestion: (id: string, input: QuestionInput) => post<Question>(`cases/${seg(id)}/questions`, input),
  editQuestion: (id: string, question: string, input: QuestionInput) =>
    put<Question>(`cases/${seg(id)}/questions/${seg(question)}`, input),
  setQuestionState: (id: string, question: string, state: "open" | "closed" | "withdrawn", note?: string) =>
    post<Question>(`cases/${seg(id)}/questions/${seg(question)}/state`, { state, note }),
  splitQuestion: (id: string, question: string) => post<TaskEnvelope>(`cases/${seg(id)}/questions/${seg(question)}/split`),
  setLeadState: (id: string, lead: string, state: "open" | "retired") =>
    post<Lead>(`cases/${seg(id)}/leads/${seg(lead)}/state`, { state }),
  checkCandidate: (id: string, candidate: string) => post<Candidate>(`cases/${seg(id)}/candidates/${seg(candidate)}/check`),
  reviewCandidate: (id: string, candidate: string) =>
    post<TaskEnvelope>(`cases/${seg(id)}/candidates/${seg(candidate)}/review`),
  recordCandidate: (id: string, candidate: string, input: RecordInput) =>
    post<TaskEnvelope>(`cases/${seg(id)}/candidates/${seg(candidate)}/record`, input),
  rejectCandidate: (id: string, candidate: string, note?: string) =>
    post<Candidate>(`cases/${seg(id)}/candidates/${seg(candidate)}/reject`, { note }),
  requests: (id: string, opts?: Opts) => get<{ requests: GrantRequest[] }>(`cases/${seg(id)}/requests`, opts),
  denyAllRequests: (id: string, note?: string) => post<{ denied: string[] }>(`cases/${seg(id)}/requests`, { action: "deny_all", note }),
  decideRequest: (id: string, request: string, input: DecideInput) =>
    post<GrantRequest>(`cases/${seg(id)}/requests/${seg(request)}/decide`, input),

  chat: (id: string, opts?: Opts) => get<ChatState>(`cases/${seg(id)}/chat`, opts),
  sendChat: (id: string, message: string) => post<TaskEnvelope>(`cases/${seg(id)}/chat`, { message }),
  clearChat: (id: string) => del<{ cleared: boolean }>(`cases/${seg(id)}/chat`),

  tasks: (caseId: string | null, opts?: Opts) =>
    get<{ tasks: Task[] }>(caseId ? `tasks?${new URLSearchParams({ case: caseId })}` : "tasks", opts),
  task: (id: string, opts?: Opts) => get<Task>(`tasks/${seg(id)}`, opts),
  cancelTask: (id: string) => post<Task>(`tasks/${seg(id)}/cancel`),
  dismissTask: (id: string) => post<Task>(`tasks/${seg(id)}/dismiss`),

  models: (opts?: Opts) => get<{ models: ModelConfig[] }>("models", opts),
  createModel: (model: ModelInput) => post<ModelConfig>("models", model),
  updateModel: (id: string, model: ModelInput) => put<ModelConfig>(`models/${seg(id)}`, model),
  deleteModel: (id: string) => del<{ deleted: string }>(`models/${seg(id)}`),
  testModel: (id: string) => post<TaskEnvelope>(`models/${seg(id)}/test`),
};
