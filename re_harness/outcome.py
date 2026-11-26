"""A per-case outcome card computed from the audit log and the investigation store. Host-only, metadata only.

It counts tool calls by decision, grants requested, issued and denied, proposals by check result and decision, and
model tokens by provider and locality. It is the baseline later changes are measured against (docs/MODELS.md).
"""

import json

from . import investigation

MAX_AUDIT = 64 * 1024 * 1024
TOOL_DECISIONS = ("dispatched", "completed", "intercepted", "failed", "investigation_write")
TOKEN_EVENTS = ("forge_chat_completed", "forge_chat_failed", "review_completed", "review_failed")


def events(folder):
    """Every audit event of the case, oldest first, read line by line within a size budget."""
    path = folder / "audit.jsonl"
    try:
        with path.open("rb") as stream:
            read = 0
            for line in stream:
                read += len(line)
                if read > MAX_AUDIT:
                    return
                try:
                    event = json.loads(line.decode("ascii"))
                except (UnicodeError, ValueError):
                    continue
                if isinstance(event, dict):
                    yield event
    except OSError:
        return


def count(table, *keys):
    for key in keys[:-1]:
        table = table.setdefault(key, {})
    table[keys[-1]] = table.get(keys[-1], 0) + 1


def number(value):
    return value if type(value) is int and value >= 0 else 0


def card(folder, data):
    tools, reasons, tokens = {}, {}, {}
    grants = {"requested": 0, "issued": 0, "denied": 0, "approved": 0}
    sessions, first, last = set(), None, None
    for event in events(folder):
        utc = event.get("utc") if isinstance(event.get("utc"), str) else None
        if utc:
            first = first or utc
            last = utc
        decision = event.get("decision")
        tool = event.get("tool") if isinstance(event.get("tool"), str) else None
        if tool and decision in TOOL_DECISIONS and isinstance(event.get("session"), str):
            count(tools, tool, decision)
            sessions.add(event["session"])
            if decision == "intercepted" and isinstance(event.get("reason"), str):
                count(reasons, event["reason"][:64])
        if decision == "grant_requested":
            grants["requested"] += 1
        elif decision == "grant" and isinstance(event.get("grant"), dict):
            grants["issued"] += 1
        elif decision == "grant_decided":
            settled = len(event["requests"]) if isinstance(event.get("requests"), list) else 1
            grants["denied" if event.get("outcome") == "denied" else "approved"] += settled
        if decision in TOKEN_EVENTS:
            provider = event.get("provider") if isinstance(event.get("provider"), str) else "unknown"
            locality = "cloud" if event.get("cloud") is True else "local"
            row = tokens.setdefault(f"{provider}/{locality}", {"provider": provider, "locality": locality,
                                                              "input": 0, "output": 0, "sessions": 0})
            row["input"] += number(event.get("tokens_in"))
            row["output"] += number(event.get("tokens_out"))
            row["sessions"] += 1
    candidates = {"total": 0, "passed": 0, "failed": 0, "not_assessed": 0, "proposed": 0, "recorded": 0,
                  "rejected": 0, "reviewed": 0}
    for row in data["candidates"]:
        candidates["total"] += 1
        result = (row.get("check") or {}).get("result")
        if result in ("passed", "failed", "not_assessed"):
            candidates[result] += 1
        if row.get("state") in ("proposed", "recorded", "rejected"):
            candidates[row["state"]] += 1
        if row.get("verdicts"):
            candidates["reviewed"] += 1
    questions = {}
    for row in data["questions"]:
        count(questions, row.get("state") if isinstance(row.get("state"), str) else "unknown")
    return {"tools": tools, "denials": reasons, "grants": grants, "candidates": candidates, "questions": questions,
            "leads": len(data["leads"]), "observations": len(data["observations"]),
            "tokens": sorted(tokens.values(), key=lambda row: (row["provider"], row["locality"])),
            "model_sessions": len(sessions), "first_utc": first, "last_utc": last}


def for_case(state, case_id, folder):
    try:
        data = investigation.load(state, case_id)
    except investigation.InvestigationError:
        data = investigation.empty()
    return card(folder, data)
