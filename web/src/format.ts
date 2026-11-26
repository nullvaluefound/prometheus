// Formatting and validation helpers. None of them produce markup: callers render the strings as text.

export const CASE_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
export const MODEL_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const DIGEST = /^[a-f0-9]{64}$/;
export const ADDRESS = /^0x[0-9a-f]{1,16}$/;
export const SOURCE_LABEL = /^[A-Za-z0-9][A-Za-z0-9 _./(),-]{0,159}$/;

// Browsers compile the HTML pattern attribute with the "v" flag, where "-", "/", "(" and ")" must be
// escaped inside a character class. These strings mirror the regular expressions above.
export const CASE_ID_PATTERN = "[a-z0-9][a-z0-9\\-]{0,47}";
export const MODEL_ID_PATTERN = "[a-z0-9][a-z0-9\\-]{0,31}";
export const DIGEST_PATTERN = "[a-f0-9]{64}";
export const ADDRESS_PATTERN = "0[xX][0-9a-fA-F]{1,16}";
export const SOURCE_PATTERN = "[A-Za-z0-9][A-Za-z0-9 _.\\/\\(\\),\\-]{0,159}";

export const MAX_UPLOAD_BYTES = 128 * 1024 * 1024;
export const MAX_CHAT_CHARS = 6000;
// Selector bounds from re_harness/policy.py. The server validates them again.
export const OFFSET_MAX = 10000;
export const LIMIT_MAX = 50;
export const LIMIT_DEFAULT = 20;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function list<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

/** A string or finite number as text; anything else becomes "". Use for every untrusted field. */
export function txt(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

export function isScalar(value: unknown): value is string | number | boolean | null {
  return value === null || ["string", "number", "boolean"].includes(typeof value);
}

export function scalarText(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  return txt(value);
}

export function compactJson(value: unknown, cap = 2000): string {
  let out: string;
  try {
    out = JSON.stringify(value) ?? "";
  } catch {
    out = "";
  }
  return out.length > cap ? out.slice(0, cap) + "…" : out;
}

const pad = (n: number) => String(n).padStart(2, "0");

export function fmtTime(iso: unknown): string {
  const raw = txt(iso);
  if (!raw) return "";
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return raw;
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`
  );
}

export function fmtAgo(iso: unknown, now = Date.now()): string {
  const raw = txt(iso);
  const time = raw ? new Date(raw).getTime() : NaN;
  if (Number.isNaN(time)) return "";
  const seconds = Math.round((now - time) / 1000);
  if (seconds < 0) return "in the future";
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 36) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}

export function fmtDuration(start: unknown, end: unknown, now = Date.now()): string {
  const from = txt(start) ? new Date(txt(start)).getTime() : NaN;
  if (Number.isNaN(from)) return "";
  const to = txt(end) ? new Date(txt(end)).getTime() : now;
  if (Number.isNaN(to) || to < from) return "";
  const seconds = Math.round((to - from) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function fmtBytes(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

export function fmtCount(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString("en-US") : "—";
}

export function short(value: unknown, keep = 12): string {
  const raw = txt(value);
  return raw.length > keep + 1 ? raw.slice(0, keep) + "…" : raw;
}

export function plural(count: number, one: string, many = one + "s"): string {
  return `${count.toLocaleString("en-US")} ${count === 1 ? one : many}`;
}

/** Decisions that a person should notice in an audit trail. */
export function decisionTone(decision: unknown): "warn" | "err" | "ok" | "muted" {
  const value = txt(decision);
  if (value === "intercepted") return "warn";
  if (value.includes("failed") || value === "denied" || value === "refused") return "err";
  if (value === "completed" || value.endsWith("_completed")) return "ok";
  return "muted";
}
