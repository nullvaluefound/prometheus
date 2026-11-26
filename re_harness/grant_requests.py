"""Pending excerpt grant requests, built from broker denials. Host-only; only the operator decides them.

A request holds the exact tool, validated arguments and audience of a call the broker refused with
operator_excerpt_grant_required. The model can add a short reason, which is untrusted text: it is shown to the
operator and never replayed to a model. Approving a request issues a grant for exactly the denied call.
"""

import datetime as dt
import json
import re
import threading
import uuid

from . import accounts, policy, runtime

LOCK = threading.Lock()
REQUEST_ID = r"[a-f0-9]{32}"
MAX_REASON = 500
MAX_PENDING = 64
KEEP_DECIDED = 200
STATES = ("pending", "approved", "denied")
DIGEST_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
ADDRESS_TOKEN = re.compile(r"(?<![0-9A-Za-z])0[xX][0-9A-Fa-f]{1,16}(?![0-9A-Za-z])")


class RequestError(ValueError):
    """A refusal with a fixed reason code."""


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def store_path(state, case_id):
    if not policy.match(case_id, policy.CASE_ID):
        raise RequestError("invalid_case")
    return accounts.folder(state) / "requests" / f"{case_id}.json"


def load(state, case_id):
    path = store_path(state, case_id)
    if not path.exists():
        return []
    rows = json.loads(path.read_text(encoding="utf-8"))
    return [row for row in rows if isinstance(row, dict) and row.get("state") in STATES] if isinstance(rows, list) else []


def save(state, case_id, rows):
    accounts.write_private(store_path(state, case_id), (json.dumps(rows, indent=1, ensure_ascii=True) + "\n").encode("ascii"))


def tokens(text):
    """SHA-256 values and addresses named in text, normalized for comparison."""
    found = {match.lower() for match in DIGEST_TOKEN.findall(text)}
    found |= {hex(int(match, 16)) for match in ADDRESS_TOKEN.findall(text)}
    return found


def clean(text):
    return "".join(ch if ch.isprintable() else " " for ch in text).strip()[:MAX_REASON]


def file(state, case_id, tool, arguments, audience, session):
    """Record a pending request for exactly this denied call. Returns (request, created)."""
    if tool not in policy.EXCERPT_ONLY or audience not in ("local", "mcp"):
        raise RequestError("not_requestable")
    arguments = policy.validate(tool, arguments)
    with LOCK:
        rows = load(state, case_id)
        for row in rows:
            if (row["state"] == "pending" and row["tool"] == tool and row["arguments"] == arguments and
                    row["audience"] == audience):
                return dict(row), False
        if sum(row["state"] == "pending" for row in rows) >= MAX_PENDING:
            raise RequestError("too_many_pending_requests")
        row = {"id": uuid.uuid4().hex, "state": "pending", "tool": tool, "arguments": arguments,
               "audience": audience, "session": session, "created_utc": now(), "reason": None, "flags": [],
               "decided_by": None, "decided_utc": None, "grant": None, "note": None}
        decided = [item for item in rows if item["state"] != "pending"]
        drop = {item["id"] for item in decided[:max(0, len(decided) - KEEP_DECIDED)]}
        rows = [item for item in rows if item["id"] not in drop] + [row]
        save(state, case_id, rows)
    runtime.audit(runtime.case_path(state, case_id), case=case_id, session=session, decision="grant_requested",
                  request=row["id"], tool=tool, arguments=arguments, audience=audience)
    return dict(row), True


def note(state, case_id, request_id, reason, session, known):
    """Attach the model's short reason to a pending request from the same session.

    flags lists SHA-256 values and addresses in the reason that are neither in the case manifest nor in this
    session's tool output: they are model-derived and nobody has verified them.
    """
    if not isinstance(request_id, str) or not policy.match(request_id, REQUEST_ID):
        raise RequestError("unknown_request")
    if not isinstance(reason, str) or not clean(reason):
        raise RequestError("invalid_reason")
    text = clean(reason)
    with LOCK:
        rows = load(state, case_id)
        row = next((item for item in rows if item["id"] == request_id), None)
        if row is None or row["session"] != session:
            raise RequestError("unknown_request")
        if row["state"] != "pending":
            raise RequestError("request_already_decided")
        row["reason"] = text
        # The request's own artifact and address are shown to the approver, so they need no flag.
        named = {value for value in row["arguments"].values() if isinstance(value, str)}
        row["flags"] = sorted(tokens(text) - set(known) - named)[:32]
        save(state, case_id, rows)
    runtime.audit(runtime.case_path(state, case_id), case=case_id, session=session, decision="grant_need_noted",
                  request=request_id, flagged=len(row["flags"]))
    return dict(row)


def pending(state, case_id, request_id):
    row = next((item for item in load(state, case_id) if item["id"] == request_id), None)
    if row is None:
        raise RequestError("unknown_request")
    if row["state"] != "pending":
        raise RequestError("request_already_decided")
    return row


def decide(state, case_id, request_id, outcome, operator, grant=None, note_text=None):
    """Mark a pending request approved (with the grant ID issued for it) or denied."""
    if outcome not in ("approved", "denied"):
        raise RequestError("invalid_decision")
    with LOCK:
        rows = load(state, case_id)
        row = next((item for item in rows if item["id"] == request_id), None)
        if row is None:
            raise RequestError("unknown_request")
        if row["state"] != "pending":
            raise RequestError("request_already_decided")
        row.update(state=outcome, decided_by=operator, decided_utc=now(), grant=grant,
                   note=clean(note_text) if isinstance(note_text, str) and note_text.strip() else None)
        save(state, case_id, rows)
    runtime.audit(runtime.case_path(state, case_id), case=case_id, decision="grant_decided", request=request_id,
                  outcome=outcome, decided_by=operator, operator=operator, via="forge",
                  **({"grant": grant} if grant else {}))
    return dict(row)


def public(row):
    arguments = row.get("arguments") if isinstance(row.get("arguments"), dict) else {}
    return {"id": row["id"], "state": row["state"], "tool": row.get("tool"), "artifact": arguments.get("artifact"),
            "selector": {key: value for key, value in arguments.items() if key != "artifact"},
            "audience": row.get("audience"), "created_utc": row.get("created_utc"), "reason": row.get("reason"),
            "flags": row.get("flags") or [], "decided_by": row.get("decided_by"),
            "decided_utc": row.get("decided_utc"), "grant": row.get("grant"), "note": row.get("note")}


def listing(state, case_id):
    rows = load(state, case_id)
    pending_rows = sorted((row for row in rows if row["state"] == "pending"), key=lambda row: row.get("created_utc") or "")
    decided = sorted((row for row in rows if row["state"] != "pending"),
                     key=lambda row: row.get("decided_utc") or "", reverse=True)
    return [public(row) for row in pending_rows + decided[:50]]
