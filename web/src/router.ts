import { useSyncExternalStore } from "react";
import { CASE_ID } from "./format";

export type CaseTab = "overview" | "artifacts" | "tools" | "findings" | "chat" | "rules" | "audit";
export const CASE_TABS: readonly { id: CaseTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "artifacts", label: "Artifacts" },
  { id: "tools", label: "Tools" },
  { id: "findings", label: "Findings" },
  { id: "chat", label: "Chat" },
  { id: "rules", label: "Rules & grants" },
  { id: "audit", label: "Audit" },
];

export type Route =
  | { name: "dashboard" }
  | { name: "cases" }
  | { name: "case"; id: string; tab: CaseTab }
  | { name: "tasks"; caseFilter: string | null }
  | { name: "models" }
  | { name: "rules" }
  | { name: "notfound" };

const TAB_IDS = new Set<string>(CASE_TABS.map((tab) => tab.id));

export function parseHash(hash: string): Route {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  const [pathPart, queryPart = ""] = raw.split("?", 2);
  const path = pathPart === "" ? "/" : pathPart;
  const parts = path.split("/").filter(Boolean);
  if (parts.length === 0) return { name: "dashboard" };
  const [head, id, tab, ...rest] = parts;
  if (rest.length) return { name: "notfound" };
  if (head === "cases") {
    if (id === undefined) return { name: "cases" };
    if (!CASE_ID.test(id)) return { name: "notfound" };
    if (tab === undefined) return { name: "case", id, tab: "overview" };
    return TAB_IDS.has(tab) ? { name: "case", id, tab: tab as CaseTab } : { name: "notfound" };
  }
  if (id !== undefined) return { name: "notfound" };
  if (head === "tasks") {
    const filter = new URLSearchParams(queryPart).get("case");
    return { name: "tasks", caseFilter: filter && CASE_ID.test(filter) ? filter : null };
  }
  if (head === "models") return { name: "models" };
  if (head === "rules") return { name: "rules" };
  return { name: "notfound" };
}

/** Links built only from validated case IDs. Anything else gets no link. */
export function caseHref(id: unknown, tab: CaseTab = "overview"): string | null {
  if (typeof id !== "string" || !CASE_ID.test(id)) return null;
  return tab === "overview" ? `#/cases/${id}` : `#/cases/${id}/${tab}`;
}

export function tasksHref(caseFilter: string | null): string {
  return caseFilter && CASE_ID.test(caseFilter) ? `#/tasks?case=${caseFilter}` : "#/tasks";
}

export function navigate(href: string): void {
  if (window.location.hash !== href) window.location.hash = href;
}

function subscribe(callback: () => void): () => void {
  window.addEventListener("hashchange", callback);
  return () => window.removeEventListener("hashchange", callback);
}

const snapshot = () => window.location.hash;

export function useRoute(): Route {
  const hash = useSyncExternalStore(subscribe, snapshot);
  return parseHash(hash);
}
