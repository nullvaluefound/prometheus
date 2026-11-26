"""The Forge JSON API (see docs/FORGE_API.md). Host-only; every route runs for a signed-in operator."""

import argparse
import contextlib
import datetime as dt
import io
import json
import os
import re
import tempfile
import threading
import uuid
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import (accounts, cli, events, evidence, forge, grant_requests, investigate, investigation, local_model,
               models, policy,
               lessons, outcome, projection, review, runtime, server, skills, tasks)

JSON_LIMIT = 64 * 1024
CHAT_ROWS = 400
ROLES = tuple(local_model.ROLES)
SETTINGS_LOCK = threading.Lock()
CHAT_LOCK = threading.Lock()
DECIDE_LOCK = threading.Lock()  # one grant per request, even when two operators approve at once


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def bad(message, code="invalid_request"):
    return ApiError(HTTPStatus.BAD_REQUEST, code, message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


# ---- Per-case Forge settings (kept outside scope.json, which the broker and Apprentices validate) -------------

def settings_path(state, case_id):
    return accounts.folder(state) / "cases" / f"{case_id}.json"


def default_settings():
    return {"title": None, "model": None, "allow_cloud": False, "role": "evidence",
            "tools": models.default_tools("evidence"), "artifacts": None, "findings": None}


def read_settings(state, case_id):
    path = settings_path(state, case_id)
    settings = default_settings()
    if path.exists():
        stored = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(stored, dict):
            settings.update({key: stored[key] for key in settings if key in stored})
    return settings


def write_settings(state, case_id, settings):
    accounts.write_private(settings_path(state, case_id),
                           (json.dumps(settings, indent=2, ensure_ascii=True) + "\n").encode("ascii"))


def update_settings(state, case_id, **changes):
    with SETTINGS_LOCK:
        settings = read_settings(state, case_id)
        settings.update(changes)
        write_settings(state, case_id, settings)
        return settings


def public_settings(settings):
    return {key: settings[key] for key in ("model", "allow_cloud", "role", "tools")}


# ---- Case helpers -------------------------------------------------------------------------------------------

def case_status(record):
    if not record.get("initialized"):
        return "Pending"
    return forge.case_status(record)


def case_ids(state):
    root = state / "cases"
    if not root.is_dir():
        return []
    return sorted(folder.name for folder in root.iterdir()
                  if folder.is_dir() and not folder.is_symlink() and policy.match(folder.name, policy.CASE_ID))


def load_case(state, case_id):
    if not isinstance(case_id, str) or not policy.match(case_id, policy.CASE_ID):
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_case", "No such case.")
    try:
        return runtime.load_case(state, case_id, allow_pending=True, allow_closed=True)
    except (OSError, ValueError, KeyError, runtime.RuntimeFailure) as error:
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_case", "No such case.") from error


def last_event_utc(folder):
    events = forge.recent_audit(folder, 1)
    return events[0].get("utc") if events else None


def case_row(state, case_id, visible):
    folder, record = load_case(state, case_id)
    settings = read_settings(state, case_id)
    return {"id": case_id, "title": settings["title"], "status": case_status(record), "model": settings["model"],
            "allow_cloud": settings["allow_cloud"], "artifacts": settings["artifacts"],
            "findings": settings["findings"], "updated_utc": last_event_utc(folder)}


def visible_cases(app):
    rows = []
    for case_id in case_ids(app.state):
        if app.visible and case_id not in app.visible:
            continue
        try:
            rows.append(case_row(app.state, case_id, app.visible))
        except ApiError:
            continue
    return rows


def require_case(app, case_id):
    if app.visible and case_id not in app.visible:
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_case", "No such case.")
    return load_case(app.state, case_id)


def require_open(record):
    if runtime.closed(record):
        raise ApiError(HTTPStatus.CONFLICT, "case_closed", "The case is closed and read-only.")
    if not record.get("initialized"):
        raise ApiError(HTTPStatus.CONFLICT, "case_pending", "The case is still being created.")


def run_cli(handler, **fields):
    """Run an operator CLI handler and return what it emitted. CLI handlers print JSON or worker text."""
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        handler(argparse.Namespace(**fields))
    text = stream.getvalue().strip()
    try:
        return json.loads(text)
    except ValueError:
        return text


def forge_audit(app, case_id, operator, **event):
    folder = runtime.case_path(app.state, case_id)
    runtime.audit(folder, case=case_id, operator=operator, via="forge", **event)
    events.bump(f"case:{case_id}")


def grant_rows(record):
    return [{"id": grant["id"], "tool": grant["tool"], "artifact": grant["arguments"].get("artifact"),
             "selector": {k: v for k, v in grant["arguments"].items() if k != "artifact"},
             "audience": grant["audience"], "expires_utc": grant["expires_utc"]}
            for grant in forge.active_grants(record) if isinstance(grant.get("arguments"), dict)]


def ledger_view(ledger):
    artifacts = []
    for digest, item in sorted(ledger["artifacts"].items())[:1024]:
        if not policy.match(digest, policy.DIGEST) or not isinstance(item, dict):
            continue
        provenance = []
        for entry in (item.get("provenance") if isinstance(item.get("provenance"), list) else [])[:16]:
            if isinstance(entry, dict):
                provenance.append({key: entry.get(key) if isinstance(entry.get(key), (str, type(None))) else None
                                   for key in ("source", "completeness", "parent", "relation", "acquired_utc")})
        artifacts.append({"sha256": digest, "size": item.get("size") if isinstance(item.get("size"), int) else None,
                          "provenance": provenance})
    findings = []
    for item in ledger["findings"][:1000]:
        if not isinstance(item, dict):
            continue
        listed = lambda key: [str(v) for v in item.get(key)[:16]] if isinstance(item.get(key), list) else []
        findings.append({"id": str(item.get("id", "")), "kind": str(item.get("kind", "")),
                         "confidence": str(item.get("confidence", "")), "claim": str(item.get("claim", "")),
                         "evidence": listed("evidence"), "artifacts": listed("artifacts"),
                         "superseded_by": item.get("superseded_by") if isinstance(item.get("superseded_by"), str) else None})
    title = ledger.get("title") if isinstance(ledger.get("title"), str) else ""
    return {"title": title, "artifacts": artifacts, "findings": findings}


def tool_arguments(tool, body):
    if tool not in policy.TOOLS:
        raise ApiError(HTTPStatus.NOT_FOUND, "unknown_tool", "No such tool.")
    if not isinstance(body, dict):
        raise bad("Send the tool arguments as an object.")
    values = {key: body[key] for key in ("artifact", "address", "offset", "limit") if body.get(key) not in (None, "")}
    try:
        return policy.validate(tool, values)
    except (ValueError, TypeError, policy.Denied) as error:
        raise bad("Those tool arguments are not valid for this tool.") from error


# ---- Grant requests and the attention queue ---------------------------------------------------------------

COLLECTIONS = ("tools", "grants", "requests", "questions", "candidates", "evidence", "leads", "investigation")
STATE_MESSAGES = {
    "question_closed": "That question is closed. Reopen it first.",
    "invalid_transition": "That question cannot move to that state from where it is.",
    "candidate_already_decided": "That proposal was already decided.",
    "too_many_questions": "This case has the most questions it can hold.",
    "investigation_busy": "Another writer holds the investigation store. Try again.",
    "investigation_full": "The investigation store is full.",
    "unknown_question": "No such question.",
    "unknown_lead": "No such lead.",
    "unknown_candidate": "No such proposed finding.",
}


UNAVAILABLE = ("investigation_unreadable", "investigation_busy", "investigation_full")


def load_investigation(state, case_id):
    try:
        return investigation.load(state, case_id)
    except investigation.InvestigationError as error:
        raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "investigation_unreadable",
                       "The case's investigation store is unreadable.") from error


def require_id(value, expression, code):
    if not policy.match(value, expression):
        raise ApiError(HTTPStatus.NOT_FOUND, code, "Not found.")


def safe_requests(state, case_id):
    try:
        return grant_requests.listing(state, case_id)
    except (OSError, ValueError):
        return []


def request_error(error):
    if str(error) == "request_already_decided":
        return ApiError(HTTPStatus.CONFLICT, "request_already_decided", "That request was already decided.")
    if str(error) == "audit_unavailable":
        return ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "audit_unavailable",
                        "The case audit is unavailable, so the decision was not recorded.")
    return ApiError(HTTPStatus.NOT_FOUND, "unknown_request", "No such request.")


FAILED_TASK_HOURS = 24


def waiting(state, cases, task_rows=()):
    """Everything that waits on an operator, newest first: grant requests, proposals, proposed and answered
    questions, and failed tasks from the last day that nobody dismissed."""
    items = []
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=FAILED_TASK_HOURS)).isoformat()
    shown = {row["id"] for row in cases}
    for task in task_rows:
        if (task.get("state") == "failed" and not task.get("dismissed") and (task.get("finished_utc") or "") >= cutoff
                and (task.get("case") is None or task.get("case") in shown)):
            items.append({"kind": "task_failed", "case": task.get("case"), "id": task["id"],
                          "title": task.get("title"), "error": task.get("error"), "utc": task.get("finished_utc")})
    for row in cases:
        if row["status"] == "Closed":
            continue  # a closed case's requests can only be denied; they wait on nobody
        for request in safe_requests(state, row["id"]):
            if request["state"] == "pending":
                items.append({"kind": "grant_request", "case": row["id"], "id": request["id"], "tool": request["tool"],
                              "artifact": request["artifact"], "audience": request["audience"],
                              "utc": request["created_utc"], "flagged": bool(request["flags"])})
        try:
            data = investigation.load(state, row["id"])
        except (OSError, ValueError):
            continue
        for candidate in data["candidates"]:
            if candidate.get("state") == "proposed":
                items.append({"kind": "candidate", "case": row["id"], "id": candidate["id"],
                              "check": (candidate.get("check") or {}).get("result"),
                              "verdict": (candidate.get("verdicts") or [{}])[-1].get("verdict"),
                              "utc": candidate.get("utc")})
        for question in data["questions"]:
            if question.get("state") in ("proposed", "answer_proposed"):
                items.append({"kind": "question_" + question["state"], "case": row["id"], "id": question["id"],
                              "utc": question.get("created_utc")})
        run = data.get("run")
        if run and (run.get("state") == "waiting" or
                    (run.get("state") in ("exhausted", "failed") and not run.get("acknowledged"))):
            need = run.get("need") if isinstance(run.get("need"), dict) else {}
            items.append({"kind": "investigation_" + run["state"], "case": row["id"], "id": run["id"],
                          "need": need.get("text") if run["state"] == "waiting" else None,
                          "flagged": bool(need.get("flags")), "error": run.get("error"),
                          "utc": run.get("updated_utc")})
    items.sort(key=lambda item: item.get("utc") or "", reverse=True)
    return {"count": len(items), "items": items[:50]}


# ---- Chat history -------------------------------------------------------------------------------------------

def chat_path(state, case_id):
    return accounts.folder(state) / "chats" / f"{case_id}.json"


def read_chat(state, case_id):
    path = chat_path(state, case_id)
    if not path.exists():
        return []
    rows = json.loads(path.read_text(encoding="utf-8"))
    return rows if isinstance(rows, list) else []


def append_chat(state, case_id, rows):
    with CHAT_LOCK:
        history = read_chat(state, case_id) + rows
        history = history[-CHAT_ROWS:]
        accounts.write_private(chat_path(state, case_id),
                               (json.dumps(history, ensure_ascii=True) + "\n").encode("ascii"))
    events.bump(f"chat:{case_id}")


def stamp(row, operator=None):
    return {"id": uuid.uuid4().hex, "utc": now(), **({"operator": operator} if operator else {}), **row}


# ---- Router -------------------------------------------------------------------------------------------------

class Api:
    def __init__(self, app):
        self.app = app
        self.state = app.state
        # A restart leaves every live investigation paused for the operator; the heartbeat re-queues running ones.
        investigate.recover(self.state, case_ids(self.state))
        self.supervisor = investigate.Supervisor(self.state, self.schedule_step, self.visible_ids).start()

    def visible_ids(self):
        return [case for case in case_ids(self.state) if not self.app.visible or case in self.app.visible]

    def schedule_step(self, case_id, chained=False):
        """Queue the next step of a case's run, unless one is already queued. Each step re-reads the case model."""
        if not chained and self.app.tasks.busy(case_id, "investigate"):
            return None
        run = investigate.current(self.state, case_id)
        if not run:
            return None
        operator = run.get("started_by") or "forge"

        def job():
            try:
                config, settings = self.case_model(case_id)
            except ApiError as error:
                latest = investigate.current(self.state, case_id)
                if latest and latest["state"] in ("queued", *investigate.ACTIVE):
                    investigate.transition(self.state, case_id, latest["id"], "failed", "forge",
                                           change=lambda value, _: value.update(error=error.message))
                raise tasks.TaskError(error.message) from error
            result = investigate.step(self.state, case_id, config, settings, operator)
            if result["next"]:
                self.schedule_step(case_id, chained=True)
            return result
        return self.app.tasks.submit("investigate", case_id, f"Investigation {run['id']} step in {case_id}", operator,
                                     job)

    def dispatch(self, handler, method, path, operator):
        """path is the request path after '<prefix>api/'. Returns (status, body)."""
        route, _, query = path.partition("?")
        parts = [part for part in route.split("/") if part]
        params = {key: values[0] for key, values in parse_qs(query, keep_blank_values=True).items()}
        key = (method, tuple("{}" if i in self.variable_positions(parts) else p for i, p in enumerate(parts)))
        table = {
            ("GET", ("me",)): self.me,
            ("GET", ("overview",)): self.overview,
            ("GET", ("policy",)): self.policy,
            ("GET", ("cases",)): self.cases,
            ("POST", ("cases",)): self.create_case,
            ("GET", ("cases", "{}")): self.case_detail,
            ("POST", ("cases", "{}", "pause")): lambda h, o, a, p: self.set_paused(h, o, a, True),
            ("POST", ("cases", "{}", "resume")): lambda h, o, a, p: self.set_paused(h, o, a, False),
            ("PUT", ("cases", "{}", "settings")): self.put_settings,
            ("POST", ("cases", "{}", "artifacts")): self.upload,
            ("POST", ("cases", "{}", "tools", "{}")): self.run_tool,
            ("POST", ("cases", "{}", "report")): self.report,
            ("GET", ("cases", "{}", "audit")): self.audit,
            ("POST", ("cases", "{}", "grants")): self.grant,
            ("DELETE", ("cases", "{}", "grants", "{}")): self.revoke,
            ("GET", ("cases", "{}", "requests")): self.requests,
            ("POST", ("cases", "{}", "requests")): self.deny_all_requests,
            ("POST", ("cases", "{}", "requests", "{}", "decide")): self.decide_request,
            ("GET", ("cases", "{}", "investigation")): self.investigation,
            ("GET", ("cases", "{}", "outcome")): self.outcome,
            ("GET", ("cases", "{}", "evidence")): self.evidence_list,
            ("GET", ("cases", "{}", "evidence", "{}")): self.evidence_entry,
            ("POST", ("cases", "{}", "questions")): self.add_question,
            ("PUT", ("cases", "{}", "questions", "{}")): self.edit_question,
            ("POST", ("cases", "{}", "questions", "{}", "state")): self.question_state,
            ("POST", ("cases", "{}", "questions", "{}", "split")): self.split_question,
            ("POST", ("cases", "{}", "leads", "{}", "state")): self.lead_state,
            ("POST", ("cases", "{}", "candidates", "{}", "check")): self.check_candidate,
            ("POST", ("cases", "{}", "candidates", "{}", "review")): self.review_candidate,
            ("POST", ("cases", "{}", "candidates", "{}", "record")): self.record_candidate,
            ("POST", ("cases", "{}", "candidates", "{}", "reject")): self.reject_candidate,
            ("POST", ("cases", "{}", "investigation", "{}")): self.investigation_action,
            ("POST", ("cases", "{}", "ask")): self.side_question,
            ("PUT", ("cases", "{}", "links")): self.set_links,
            ("GET", ("cases", "{}", "chat")): self.chat,
            ("POST", ("cases", "{}", "chat")): self.send_chat,
            ("DELETE", ("cases", "{}", "chat")): self.clear_chat,
            ("GET", ("tasks",)): self.task_list,
            ("GET", ("tasks", "{}")): self.task,
            ("POST", ("tasks", "{}", "cancel")): self.cancel_task,
            ("POST", ("tasks", "{}", "dismiss")): self.dismiss_task,
            ("GET", ("lessons",)): self.lessons,
            ("PUT", ("lessons",)): self.set_lessons_mode,
            ("POST", ("lessons", "extract")): self.extract_lessons,
            ("POST", ("lessons", "{}", "{}")): self.change_lesson,
            ("GET", ("models",)): self.model_list,
            ("POST", ("models",)): self.create_model,
            ("PUT", ("models", "{}")): self.update_model,
            ("DELETE", ("models", "{}")): self.delete_model,
            ("POST", ("models", "{}", "test")): self.test_model,
        }
        action = table.get(key)
        if action is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "No such API route.")
        args = [parts[i] for i in self.variable_positions(parts)]
        return action(handler, operator, args, params)

    @staticmethod
    def variable_positions(parts):
        if not parts:
            return ()
        if parts[0] == "lessons" and len(parts) == 3:
            return (1, 2)
        if parts[0] in ("cases", "models", "tasks"):
            if len(parts) >= 2:
                if parts[0] == "cases" and len(parts) in (4, 5) and parts[2] in COLLECTIONS:
                    return (1, 3)
                return (1,)
        return ()

    # -- body helpers --

    def body(self, handler):
        if handler.headers.get_content_type() != "application/json":
            raise bad("Send JSON with Content-Type application/json.")
        data = handler.read_body(JSON_LIMIT)
        try:
            return server.strict_json(data)
        except (ValueError, RecursionError, UnicodeError) as error:
            raise bad("The request body is not valid JSON.") from error

    # -- session and overview --

    def me(self, handler, operator, args, params):
        return HTTPStatus.OK, {"user": operator, "session_expires_utc": handler.session_expires}

    def overview(self, handler, operator, args, params):
        cases = visible_cases(self.app)
        queue = self.app.tasks.listing(limit=100)
        running = next((t for t in queue if t["state"] == "running"), None)
        audit = []
        for row in cases:
            folder = runtime.case_path(self.state, row["id"])
            audit += [{**event, "case": row["id"]} for event in forge.recent_audit(folder, 20)]
        audit.sort(key=lambda event: event.get("utc", ""), reverse=True)
        return HTTPStatus.OK, {
            "cases": cases, "waiting": waiting(self.state, cases, self.app.tasks.listing(limit=500)),
            "apprentices": [{"name": name, "verified": ok} for name, ok in forge.baseline_tools(self.state)],
            "tasks": {"queued": sum(t["state"] == "queued" for t in queue), "running": running, "recent": queue[:10]},
            "models": len(models.listing(self.state)), "audit": audit[:20]}

    def policy(self, handler, operator, args, params):
        return HTTPStatus.OK, {
            "tools": [{"name": name, "description": text, "excerpt_only": name in policy.EXCERPT_ONLY,
                       "paged": name in policy.PAGED, "addressed": name in policy.ADDRESSED,
                       "timeout_s": runtime.tool_timeout(name)} for name, text in policy.TOOLS.items()],
            "denied": ["run_ghidra_script"],
            "state_tools": [{"name": name, "description": text, "writes": name in investigation.WRITES}
                            for name, text in investigation.TOOLS.items()],
            "roles": {role: sorted(tools) for role, tools in local_model.ROLES.items()},
            "skills": {role: [{"name": name, "description": text} for name, text in skills.visible(role)]
                       for role in local_model.ROLES},
            "skill_gaps": skills.gaps(self.state),
            "limits": {"max_tool_calls": policy.MAX_TOOL_CALLS, "max_excerpt_bytes": policy.MAX_EXCERPT,
                       "max_artifact_bytes": policy.MAX_ARTIFACT, "chat_max_turns": models.MAX_TURNS,
                       "chat_max_calls_per_turn": models.MAX_CALLS}}

    # -- cases --

    def cases(self, handler, operator, args, params):
        return HTTPStatus.OK, {"cases": visible_cases(self.app)}

    def create_case(self, handler, operator, args, params):
        body = self.body(handler)
        case_id, title = body.get("id"), body.get("title")
        if not isinstance(case_id, str) or not policy.match(case_id, policy.CASE_ID):
            raise bad("Case IDs are 1-48 lowercase letters, digits or dashes, starting with a letter or digit.")
        if not isinstance(title, str) or not 1 <= len(title) <= 160 or not policy.match(title, cli.LABEL):
            raise bad("Give a short title of plain letters, digits and punctuation.")
        if self.app.visible:
            raise ApiError(HTTPStatus.FORBIDDEN, "case_scope_fixed", "This Forge only shows its configured cases.")
        if runtime.case_path(self.state, case_id).exists():
            raise ApiError(HTTPStatus.CONFLICT, "case_exists", "A case with that ID already exists.")
        update_settings(self.state, case_id, title=title)

        def job():
            run_cli(cli.init_case, case=case_id, title=title)
            forge_audit(self.app, case_id, operator, decision="forge_case_created")
            return {"case": case_id}
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("create_case", case_id, f"Create case {case_id}",
                                                                   operator, job)}

    def case_detail(self, handler, operator, args, params):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        settings = read_settings(self.state, case_id)
        ledger = None
        if record.get("initialized"):
            try:
                ledger = ledger_view(forge.case_ledger(record))
                update_settings(self.state, case_id, artifacts=len(ledger["artifacts"]),
                                findings=len(ledger["findings"]))
            except forge.BROWSER_ERRORS:
                ledger = None
        rules = record.get("yara_rules")
        return HTTPStatus.OK, {
            "id": case_id, "title": settings["title"], "status": case_status(record), "image": record["image"],
            "engine": record["engine"],
            "yara_rules": {"sha256": rules["sha256"], "rules": rules.get("rules")} if isinstance(rules, dict) else None,
            "settings": public_settings(settings), "ledger": ledger, "grants": grant_rows(record),
            "pending_requests": 0 if runtime.closed(record) else sum(row["state"] == "pending"
                                                                     for row in safe_requests(self.state, case_id)),
            "waiting": 0 if runtime.closed(record) else sum(
                item["case"] == case_id for item in waiting(self.state, [{"id": case_id, "status": case_status(record)}],
                                                            self.app.tasks.listing(case=case_id, limit=100))["items"]),
            "audit": forge.recent_audit(folder, 50)}

    def set_paused(self, handler, operator, args, paused):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        require_open(record)
        try:
            with runtime.operator_lock(folder):
                _, record = runtime.load_case(self.state, case_id)
                if record["paused"] != paused:
                    record["paused"] = paused
                    runtime.audit(folder, case=case_id, decision="pause" if paused else "resume", operator=operator,
                                  via="forge")
                    cli.atomic_json(folder / "scope.json", record)
        except runtime.RuntimeFailure as error:
            raise ApiError(HTTPStatus.CONFLICT, "case_busy", "Another operator command holds this case.") from error
        events.bump(f"case:{case_id}")
        return HTTPStatus.OK, {"status": "Paused" if paused else "Ready"}

    def put_settings(self, handler, operator, args, params):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        if runtime.closed(record):
            raise ApiError(HTTPStatus.CONFLICT, "case_closed", "The case is closed and read-only.")
        body = self.body(handler)
        model_id, allow_cloud, role, tools_ = (body.get(key) for key in ("model", "allow_cloud", "role", "tools"))
        if role not in ROLES:
            raise bad("Pick a role: " + ", ".join(ROLES) + ".")
        if not isinstance(allow_cloud, bool):
            raise bad("allow_cloud must be true or false.")
        if not isinstance(tools_, list) or not all(isinstance(t, str) for t in tools_) or \
                not set(tools_) <= local_model.ROLES[role]:
            raise bad("The tool allowlist must be a subset of the role's tools.")
        if model_id is not None:
            try:
                config = models.get(self.state, model_id)
            except models.ModelError as error:
                raise bad("Unknown model.") from error
            if models.is_cloud(config) and not allow_cloud:
                raise ApiError(HTTPStatus.CONFLICT, "cloud_not_allowed",
                               "Allow cloud models for this case before selecting a cloud model.")
        settings = update_settings(self.state, case_id, model=model_id, allow_cloud=allow_cloud, role=role,
                                   tools=sorted(set(tools_)))
        forge_audit(self.app, case_id, operator, decision="forge_settings_changed", role=role,
                    reason=f"model={model_id or 'none'} cloud={'yes' if allow_cloud else 'no'}")
        return HTTPStatus.OK, public_settings(settings)

    def upload(self, handler, operator, args, params):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        require_open(record)
        if record["paused"]:
            raise ApiError(HTTPStatus.CONFLICT, "case_paused", "Resume the case before adding artifacts.")
        source = params.get("source", "")
        completeness = params.get("completeness", "unknown")
        if not policy.match(source, cli.LABEL):
            raise bad("Give a short source label without credentials or URLs.")
        if completeness not in ("complete", "partial", "unknown"):
            raise bad("Completeness must be complete, partial or unknown.")
        if handler.headers.get_content_type() != "application/octet-stream":
            raise bad("Upload the raw file as application/octet-stream.")
        uploads = accounts.folder(self.state) / "uploads"
        uploads.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=uploads, prefix="upload-")
        path = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                handler.copy_body(stream, policy.MAX_ARTIFACT)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

        def job():
            try:
                result = run_cli(cli.operator_action, case=case_id, command="ingest", input=path, source=source,
                                 parent=None, relation=None, completeness=completeness)
            finally:
                path.unlink(missing_ok=True)
            digest = result.get("sha256") if isinstance(result, dict) else None
            forge_audit(self.app, case_id, operator, decision="forge_upload_ingested",
                        **({"artifact": digest} if isinstance(digest, str) else {}))
            return {"sha256": digest, "size": result.get("size") if isinstance(result, dict) else None}
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("ingest", case_id, f"Ingest upload into {case_id}",
                                                                   operator, job)}

    def run_tool(self, handler, operator, args, params):
        case_id, tool = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        arguments = tool_arguments(tool, self.body(handler))

        def job():
            with runtime.operator_lock(folder):
                _, scope = runtime.load_case(self.state, case_id)
                if scope["paused"]:
                    raise tasks.TaskError("The case is paused. Resume it first.")
                event = {"case": case_id, "operation": "inspect", "tool": tool, "artifact": arguments["artifact"],
                         "arguments": arguments, "operator": operator, "via": "forge"}
                runtime.audit(folder, decision="operator_requested", **event)
                try:
                    request = {"tool": tool, "arguments": arguments, "excerpt": True}
                    if tool == "yara_scan":
                        request["rules"] = runtime.yara_rules(scope)
                    code, raw = runtime.worker(scope, ["analyze"], request=json.dumps(request).encode("ascii"),
                                               timeout=runtime.tool_timeout(tool))
                    if code:
                        raise tasks.TaskError("The offline Apprentice did not complete the inspection.")
                    reply = projection.project(server.strict_json(raw), tool, arguments, True, request.get("rules"))
                except BaseException:
                    runtime.audit(folder, decision="operator_failed", reason="operation_failed", **event)
                    raise
                runtime.audit(folder, decision="operator_completed", **event)
            return reply
        title = f"{tool} on {arguments['artifact'][:12]}…"
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("tool", case_id, title, operator, job)}

    def report(self, handler, operator, args, params):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        require_open(record)

        def job():
            run_cli(cli.operator_action, case=case_id, command="report")
            _, scope = runtime.load_case(self.state, case_id)
            text = cli.call_worker(scope, ["export", "report.md"], cap=2 * 1024 * 1024 - 4096)
            forge_audit(self.app, case_id, operator, decision="forge_report_generated")
            return {"markdown": text.decode("utf-8", "replace")}
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("report", case_id, f"Report for {case_id}",
                                                                   operator, job)}

    def audit(self, handler, operator, args, params):
        folder, _ = require_case(self.app, args[0])
        return HTTPStatus.OK, {"audit": forge.recent_audit(folder, 200)}

    # -- grants --

    def grant(self, handler, operator, args, params):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        require_open(record)
        body = self.body(handler)
        tool, audience, minutes = body.get("tool"), body.get("audience"), body.get("minutes")
        if tool not in cli.EXCERPTS:
            raise bad("Grants apply to excerpt-capable tools only.")
        if audience not in ("local", "mcp"):
            raise bad("Audience must be local or mcp.")
        if type(minutes) is not int or not 1 <= minutes <= 60:
            raise bad("Grants last 1-60 minutes.")
        arguments = tool_arguments(tool, body)
        try:
            event = run_cli(cli.change_scope, case=case_id, command="grant", tool=tool, audience=audience,
                            minutes=minutes, **{key: arguments.get(key) for key in ("artifact", "address", "offset",
                                                                                     "limit")})
        except runtime.RuntimeFailure as error:
            raise ApiError(HTTPStatus.CONFLICT, "grant_refused", str(error)) from error
        forge_audit(self.app, case_id, operator, decision="forge_grant", tool=tool, audience=audience,
                    reason="grant " + event["grant"]["id"][:8])
        grant = event["grant"]
        return HTTPStatus.OK, {"id": grant["id"], "tool": grant["tool"], "artifact": grant["arguments"]["artifact"],
                               "selector": {k: v for k, v in grant["arguments"].items() if k != "artifact"},
                               "audience": grant["audience"], "expires_utc": grant["expires_utc"]}

    def revoke(self, handler, operator, args, params):
        case_id, grant_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        if not re.fullmatch(r"[a-f0-9]{32}", grant_id):
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_grant", "No such grant.")
        try:
            run_cli(cli.change_scope, case=case_id, command="revoke", grant=grant_id)
        except runtime.RuntimeFailure as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_grant", "No such grant.") from error
        forge_audit(self.app, case_id, operator, decision="forge_revoke", reason="grant " + grant_id[:8])
        return HTTPStatus.OK, {"revoked": grant_id}

    # -- grant requests filed from broker denials --

    def requests(self, handler, operator, args, params):
        require_case(self.app, args[0])
        return HTTPStatus.OK, {"requests": safe_requests(self.state, args[0])}

    def deny_all_requests(self, handler, operator, args, params):
        """POST {action: "deny_all", note?} denies every pending request at once. A closed case allows it too."""
        case_id = args[0]
        require_case(self.app, case_id)
        body = self.body(handler)
        note = body.get("note")
        if body.get("action") != "deny_all":
            raise bad("Send action deny_all.")
        if note is not None and (not isinstance(note, str) or len(note) > 200):
            raise bad("Keep the note to 200 characters.")
        with DECIDE_LOCK:
            try:
                denied = grant_requests.deny_all(self.state, case_id, operator, note)
            except grant_requests.RequestError as error:
                raise request_error(error) from error
        return HTTPStatus.OK, {"denied": denied}

    def decide_request(self, handler, operator, args, params):
        """Approve issues a grant for exactly the denied call and audience; deny records the operator's note.

        A closed case can still deny, so its queue empties; it cannot approve.
        """
        case_id, request_id = args
        folder, record = require_case(self.app, case_id)
        if not policy.match(request_id, grant_requests.REQUEST_ID):
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_request", "No such request.")
        body = self.body(handler)
        decision, minutes, note = body.get("decision"), body.get("minutes"), body.get("note")
        if decision not in ("approve", "deny"):
            raise bad("Decide approve or deny.")
        if decision == "approve":
            require_open(record)
        if note is not None and (not isinstance(note, str) or len(note) > 200):
            raise bad("Keep the note to 200 characters.")
        with DECIDE_LOCK:
            return self.decide_locked(case_id, request_id, decision, minutes, note, operator)

    def decide_locked(self, case_id, request_id, decision, minutes, note, operator):
        try:
            row = grant_requests.pending(self.state, case_id, request_id)
        except grant_requests.RequestError as error:
            raise request_error(error) from error
        grant = None
        if decision == "approve":
            if type(minutes) is not int or not 1 <= minutes <= 60:
                raise bad("Grants last 1-60 minutes.")
            arguments = row["arguments"]
            try:
                event = run_cli(cli.change_scope, case=case_id, command="grant", tool=row["tool"],
                                audience=row["audience"], minutes=minutes,
                                **{key: arguments.get(key) for key in ("artifact", "address", "offset", "limit")})
            except runtime.RuntimeFailure as error:
                raise ApiError(HTTPStatus.CONFLICT, "grant_refused", str(error)) from error
            grant = event["grant"]["id"]
            forge_audit(self.app, case_id, operator, decision="forge_grant", tool=row["tool"],
                        audience=row["audience"], reason="grant " + grant[:8])
        try:
            decided = grant_requests.decide(self.state, case_id, request_id,
                                            "approved" if decision == "approve" else "denied", operator, grant, note)
        except grant_requests.RequestError as error:
            raise request_error(error) from error
        return HTTPStatus.OK, grant_requests.public(decided)

    # -- investigation state, evidence and proposed findings --

    def investigation(self, handler, operator, args, params):
        require_case(self.app, args[0])
        return HTTPStatus.OK, investigation.operator_view(load_investigation(self.state, args[0]))

    def investigation_action(self, handler, operator, args, params):
        """start, pause, resume, cancel, acknowledge or message the case's investigation run."""
        case_id, action = args
        folder, record = require_case(self.app, case_id)
        body = self.body(handler)
        if action not in ("start", "pause", "resume", "cancel", "acknowledge", "message"):
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "No such investigation action.")
        if action in ("start", "resume", "message"):
            require_open(record)
            if record["paused"]:
                raise ApiError(HTTPStatus.CONFLICT, "case_paused", "Resume the case first.")
        if action == "start":
            self.case_model(case_id)
            budgets, role = body.get("budgets"), body.get("lead_role", "evidence")
            if budgets is not None and not isinstance(budgets, dict):
                raise bad("Send budgets as an object of calls, tokens and minutes.")
            try:
                manifest = forge.case_ledger(record)["artifacts"]
            except forge.BROWSER_ERRORS as error:
                raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "ledger_unavailable",
                               "The case ledger could not be read to check the questions.") from error
            run = self.run_write(lambda: investigate.start(self.state, case_id, operator, manifest, budgets, role))
            self.schedule_step(case_id)
            return HTTPStatus.OK, run
        text = body.get("text") if action == "message" else None
        if action == "message" and (not isinstance(text, str) or not 1 <= len(text.strip()) <= 1000):
            raise bad("Write a message of 1-1000 characters for the next lead.")
        run = self.run_write(lambda: investigate.operator_action(self.state, case_id, action, operator, text))
        if action == "resume":
            self.schedule_step(case_id)
        return HTTPStatus.OK, run

    def set_links(self, handler, operator, args, params):
        """Link prior cases. Their recorded findings, not bytes, appear read-only in case_overview, marked inherited."""
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        require_open(record)
        links = self.body(handler).get("cases")
        if (not isinstance(links, list) or len(links) > investigation.MAX_LINKS or
                not all(isinstance(item, str) and policy.match(item, policy.CASE_ID) for item in links)):
            raise bad(f"Link up to {investigation.MAX_LINKS} case IDs.")
        links = list(dict.fromkeys(links))
        if case_id in links:
            raise bad("A case cannot link itself.")
        records = {}
        for linked in links:
            _, linked_record = require_case(self.app, linked)
            if not linked_record.get("initialized"):
                raise bad("Link only cases that finished setup.")
            records[linked] = linked_record

        def job():
            snapshots = {}
            for linked, linked_record in records.items():
                try:
                    snapshots[linked] = investigation.inherited_rows(linked, forge.case_ledger(linked_record))
                except forge.BROWSER_ERRORS as error:
                    raise tasks.TaskError(f"The ledger of {linked} could not be read.") from error
            result = investigation.set_links(self.state, case_id, links, snapshots, operator)
            forge_audit(self.app, case_id, operator, decision="investigation_write", operation="cases_linked",
                        linked=links)
            return result
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("link_cases", case_id, f"Link cases to {case_id}",
                                                                   operator, job)}

    def side_question(self, handler, operator, args, params):
        """Ask about the last chat or the investigation. Nothing is written to either; the answer is the task result."""
        case_id = args[0]
        require_case(self.app, case_id)
        body = self.body(handler)
        question, source = body.get("question"), body.get("source")
        if source not in ("chat", "investigation"):
            raise bad("Ask about the chat or the investigation.")
        if not isinstance(question, str) or not 1 <= len(question.strip()) <= 2000:
            raise bad("Ask a question of 1-2000 characters.")
        config, settings = self.case_model(case_id)
        history = read_chat(self.state, case_id) if source == "chat" else []

        def job():
            return models.side_question(self.state, case_id, config, settings, source, question, history, operator)
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("side_question", case_id,
                                                                   f"Side question in {case_id}", operator, job)}

    def run_write(self, write):
        try:
            return write()
        except investigation.InvestigationError as error:
            reason = str(error)
            messages = {"investigation_active": "An investigation is already running for this case.",
                        "no_usable_question": "Add an open question that names an admitted artifact and a checkable "
                                              "outcome first.",
                        "invalid_transition": "The investigation cannot do that from its current state.",
                        "unknown_run": "This case has no investigation run.",
                        "invalid_budget": "Budgets: calls 8-2000, tokens 10000-20000000, minutes 5-1440.",
                        "invalid_role": "The lead role must be native or evidence."}
            status = (HTTPStatus.NOT_FOUND if reason == "unknown_run" else
                      HTTPStatus.BAD_REQUEST if reason in ("invalid_budget", "invalid_role") else
                      HTTPStatus.SERVICE_UNAVAILABLE if reason in UNAVAILABLE else HTTPStatus.CONFLICT)
            raise ApiError(status, reason, messages.get(reason, "The investigation refused that change.")) from error

    def outcome(self, handler, operator, args, params):
        folder, _ = require_case(self.app, args[0])
        return HTTPStatus.OK, outcome.for_case(self.state, args[0], folder)

    def evidence_list(self, handler, operator, args, params):
        folder, _ = require_case(self.app, args[0])
        return HTTPStatus.OK, {"evidence": evidence.listing(folder)}

    def evidence_entry(self, handler, operator, args, params):
        folder, _ = require_case(self.app, args[0])
        try:
            return HTTPStatus.OK, evidence.summary(evidence.load(folder, args[1]))
        except evidence.EvidenceError as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_evidence", "No such evidence in this case.") from error

    def question_body(self, handler, record):
        body = self.body(handler)
        text, outcome, artifacts = body.get("text"), body.get("outcome"), body.get("artifacts", [])
        if not isinstance(text, str) or not 1 <= len(investigation.clean(text)) <= 500:
            raise bad("Write the question in 1-500 characters.")
        if not isinstance(outcome, str) or len(outcome) > 300:
            raise bad("State the checkable outcome in at most 300 characters.")
        if (not isinstance(artifacts, list) or len(artifacts) > 8 or
                not all(policy.match(item, policy.DIGEST) for item in artifacts)):
            raise bad("Name up to 8 artifacts by their lowercase SHA-256.")
        artifacts = list(dict.fromkeys(artifacts))
        if artifacts:
            try:
                manifest = forge.case_ledger(record)["artifacts"]
            except forge.BROWSER_ERRORS as error:
                raise ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "ledger_unavailable",
                               "The case ledger could not be read to check those artifacts.") from error
            if any(digest not in manifest for digest in artifacts):
                raise bad("Every artifact must be admitted to this case.", "artifact_not_admitted")
        return investigation.clean(text), investigation.clean(outcome), artifacts

    def add_question(self, handler, operator, args, params):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        require_open(record)
        text, outcome, artifacts = self.question_body(handler, record)
        row = self.state_write(case_id, operator, "question", lambda: investigation.add_question(
            self.state, case_id, text, outcome, artifacts, operator))
        return HTTPStatus.OK, row

    def edit_question(self, handler, operator, args, params):
        case_id, question_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        require_id(question_id, investigation.QUESTION_ID, "unknown_question")
        text, outcome, artifacts = self.question_body(handler, record)
        return HTTPStatus.OK, self.state_write(case_id, operator, "question", lambda: investigation.edit_question(
            self.state, case_id, question_id, text, outcome, artifacts), question=question_id)

    def question_state(self, handler, operator, args, params):
        case_id, question_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        require_id(question_id, investigation.QUESTION_ID, "unknown_question")
        body = self.body(handler)
        target, note = body.get("state"), body.get("note")
        if target not in ("open", "closed", "withdrawn"):
            raise bad("Set the question to open, closed or withdrawn.")
        if note is not None and (not isinstance(note, str) or len(note) > 300):
            raise bad("Keep the note to 300 characters.")
        row = self.state_write(case_id, operator, "question_" + target, lambda: (
            investigation.set_question_state(self.state, case_id, question_id, target, operator,
                                             investigation.clean(note) if note else None)), question=question_id)
        if target in ("closed", "withdrawn"):
            # Only the operator closes questions; closing the last one answers the run.
            try:
                investigate.check_answered(self.state, case_id, operator)
            except investigation.InvestigationError:
                pass
        return HTTPStatus.OK, row

    def split_question(self, handler, operator, args, params):
        case_id, question_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        require_id(question_id, investigation.QUESTION_ID, "unknown_question")
        config, settings = self.case_model(case_id)
        question = next((row for row in load_investigation(self.state, case_id)["questions"]
                         if row["id"] == question_id), None)
        if question is None or question["state"] != "open":
            raise ApiError(HTTPStatus.CONFLICT, "question_not_open", "Only an open question can be split.")

        def job():
            proposed = models.split_question(config, question)
            stamp = {"author": "model", "model": config["model"], "audience": "mcp" if models.is_cloud(config)
                     else "local", "grants": []}
            ids = [investigation.add_question(self.state, case_id, text, outcome, question.get("artifacts") or [],
                                              operator, parent=question_id, proposed=True, stamp=stamp)["id"]
                   for text, outcome in proposed]
            forge_audit(self.app, case_id, operator, decision="investigation_write", operation="question_split",
                        question=question_id, proposed=ids)
            return {"proposed": ids}
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("split", case_id, f"Split {question_id} in {case_id}",
                                                                   operator, job)}

    def lead_state(self, handler, operator, args, params):
        case_id, lead_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        require_id(lead_id, investigation.LEAD_ID, "unknown_lead")
        target = self.body(handler).get("state")
        if target not in ("open", "retired"):
            raise bad("Set the lead to open or retired.")
        return HTTPStatus.OK, self.state_write(case_id, operator, "lead_" + target, lambda: (
            investigation.set_lead_state(self.state, case_id, lead_id, target)), lead=lead_id)

    def candidate(self, case_id, candidate_id):
        require_id(candidate_id, investigation.CANDIDATE_ID, "unknown_candidate")
        rows = load_investigation(self.state, case_id)["candidates"]
        row = next((item for item in rows if item["id"] == candidate_id), None)
        if row is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_candidate", "No such proposed finding.")
        return row

    def check_candidate(self, handler, operator, args, params):
        case_id, candidate_id = args
        folder, record = require_case(self.app, case_id)
        self.candidate(case_id, candidate_id)
        manifest = lambda: forge.case_ledger(record)["artifacts"]  # noqa: E731
        return HTTPStatus.OK, self.state_write(case_id, operator, "candidate_check", lambda: (
            investigation.recheck_candidate(self.state, case_id, candidate_id, folder, manifest)),
            candidate=candidate_id)

    def review_candidate(self, handler, operator, args, params):
        case_id, candidate_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        if self.candidate(case_id, candidate_id)["state"] != "proposed":
            raise ApiError(HTTPStatus.CONFLICT, "candidate_already_decided", "That proposal was already decided.")
        config, settings = self.case_model(case_id)

        def job():
            verdict = review.run(self.state, case_id, config, settings, candidate_id, operator)
            return {"candidate": candidate_id, "verdict": verdict["verdict"]}
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("review", case_id,
                                                                   f"Review {candidate_id} in {case_id}", operator, job)}

    def record_candidate(self, handler, operator, args, params):
        """Record a proposal as a ledger finding through the operator finding path. The operator may edit it first."""
        case_id, candidate_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        row = self.candidate(case_id, candidate_id)
        if row["state"] != "proposed":
            raise ApiError(HTTPStatus.CONFLICT, "candidate_already_decided", "That proposal was already decided.")
        body = self.body(handler)
        claim = body.get("claim", row["claim"])
        kind = body.get("kind", row["kind"])
        confidence = body.get("confidence", row["confidence"])
        if not isinstance(claim, str) or not 1 <= len(claim.strip()) <= cli.MAX_CLAIM:
            raise bad(f"The claim must be 1-{cli.MAX_CLAIM} characters.")
        if kind not in investigation.FINDING_KINDS or confidence not in investigation.CONFIDENCE:
            raise bad("Pick a valid kind and confidence.")
        cited = ["evidence:" + evidence_id for evidence_id in (row.get("evidence") or [])][:cli.MAX_EVIDENCE]
        if evidence.missing(folder, cited):
            raise ApiError(HTTPStatus.CONFLICT, "unknown_evidence", "A cited evidence id is missing from this case.")
        cited = cited or [f"Proposal {candidate_id}, no tool evidence cited"]
        # Claim the candidate now, so a second record or a reject cannot race this one to the ledger.
        self.state_write(case_id, operator, "candidate_recording", lambda: investigation.claim_candidate(
            self.state, case_id, candidate_id, operator), candidate=candidate_id)

        def job():
            if self.candidate(case_id, candidate_id)["state"] != "recording":
                raise tasks.TaskError("The proposal is no longer waiting to be recorded.")
            try:
                result = run_cli(cli.operator_action, case=case_id, command="finding",
                                 artifact=list(row["artifacts"]), kind=kind, confidence=confidence,
                                 claim=investigation.clean(claim), evidence=cited, supersedes=None)
            except BaseException:
                investigation.release_candidate(self.state, case_id, candidate_id)
                raise
            finding = result.get("id") if isinstance(result, dict) else None
            investigation.decide_candidate(self.state, case_id, candidate_id, "recorded", operator, finding)
            forge_audit(self.app, case_id, operator, decision="investigation_write", operation="candidate_recorded",
                        candidate=candidate_id, finding=finding)
            return {"candidate": candidate_id, "finding": finding}
        try:
            task = self.app.tasks.submit("record_finding", case_id, f"Record {candidate_id} in {case_id}", operator,
                                         job)
        except BaseException:
            investigation.release_candidate(self.state, case_id, candidate_id)
            raise
        return HTTPStatus.ACCEPTED, {"task": task}

    def reject_candidate(self, handler, operator, args, params):
        case_id, candidate_id = args
        folder, record = require_case(self.app, case_id)
        require_open(record)
        self.candidate(case_id, candidate_id)
        note = self.body(handler).get("note")
        if note is not None and (not isinstance(note, str) or len(note) > 300):
            raise bad("Keep the note to 300 characters.")
        return HTTPStatus.OK, self.state_write(case_id, operator, "candidate_rejected", lambda: (
            investigation.decide_candidate(self.state, case_id, candidate_id, "rejected", operator,
                                           note=investigation.clean(note) if note else None)), candidate=candidate_id)

    def state_write(self, case_id, operator, operation, write, **ids):
        try:
            row = write()
        except investigation.InvestigationError as error:
            reason = str(error)
            status = (HTTPStatus.NOT_FOUND if reason.startswith("unknown_") else
                      HTTPStatus.SERVICE_UNAVAILABLE if reason in UNAVAILABLE else HTTPStatus.CONFLICT)
            message = STATE_MESSAGES.get(reason, "The investigation store refused that change.")
            raise ApiError(status, reason, message) from error
        if operation == "question":
            ids.setdefault("question", row["id"])
        forge_audit(self.app, case_id, operator, decision="investigation_write", operation=operation, **ids)
        return row

    def case_model(self, case_id):
        settings = read_settings(self.state, case_id)
        if not settings["model"]:
            raise ApiError(HTTPStatus.CONFLICT, "no_model", "Pick a model for this case on its Rules tab first.")
        try:
            config = models.get(self.state, settings["model"])
        except models.ModelError as error:
            raise ApiError(HTTPStatus.CONFLICT, "no_model", "The case's model no longer exists.") from error
        if models.is_cloud(config) and not settings["allow_cloud"]:
            raise ApiError(HTTPStatus.CONFLICT, "cloud_not_allowed", "This case does not allow cloud models.")
        return config, settings

    # -- chat --

    def chat(self, handler, operator, args, params):
        case_id = args[0]
        require_case(self.app, case_id)
        return HTTPStatus.OK, {"messages": read_chat(self.state, case_id), "busy": self.app.tasks.busy(case_id, "chat")}

    def send_chat(self, handler, operator, args, params):
        case_id = args[0]
        folder, record = require_case(self.app, case_id)
        require_open(record)
        message = self.body(handler).get("message")
        if not isinstance(message, str) or not 1 <= len(message.strip()) <= models.MAX_PROMPT:
            raise bad(f"Send a message of 1-{models.MAX_PROMPT} characters.")
        settings = read_settings(self.state, case_id)
        if not settings["model"]:
            raise ApiError(HTTPStatus.CONFLICT, "no_model", "Pick a model for this case on its Rules tab first.")
        try:
            config = models.get(self.state, settings["model"])
        except models.ModelError as error:
            raise ApiError(HTTPStatus.CONFLICT, "no_model", "The case's model no longer exists.") from error
        if models.is_cloud(config) and not settings["allow_cloud"]:
            raise ApiError(HTTPStatus.CONFLICT, "cloud_not_allowed", "This case does not allow cloud models.")
        if self.app.tasks.busy(case_id, "chat"):
            raise ApiError(HTTPStatus.CONFLICT, "chat_busy", "The model is still answering the last message.")
        history = read_chat(self.state, case_id)
        append_chat(self.state, case_id, [stamp({"role": "user", "text": message}, operator)])

        def job():
            try:
                rows = models.converse(self.state, case_id, config, settings, history, message, operator)
            except Exception as error:
                append_chat(self.state, case_id, [stamp({"role": "assistant", "text": "", "model": config["model"],
                                                         "error": tasks.safe_error(error)
                                                         if not isinstance(error, models.ModelError) else str(error)})])
                raise
            append_chat(self.state, case_id, [stamp(row) for row in rows])
            return {"messages": len(rows)}
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("chat", case_id, f"Chat in {case_id}", operator, job)}

    def clear_chat(self, handler, operator, args, params):
        case_id = args[0]
        require_case(self.app, case_id)
        if self.app.tasks.busy(case_id, "chat"):
            raise ApiError(HTTPStatus.CONFLICT, "chat_busy", "Wait for the model to finish first.")
        with CHAT_LOCK:
            chat_path(self.state, case_id).unlink(missing_ok=True)
        events.bump(f"chat:{case_id}")
        forge_audit(self.app, case_id, operator, decision="forge_chat_cleared")
        return HTTPStatus.OK, {"cleared": True}

    # -- tasks --

    def task_list(self, handler, operator, args, params):
        case = params.get("case")
        return HTTPStatus.OK, {"tasks": self.app.tasks.listing(case=case or None)}

    def task(self, handler, operator, args, params):
        task = self.app.tasks.get(args[0])
        if not task:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_task", "No such task.")
        return HTTPStatus.OK, task

    def dismiss_task(self, handler, operator, args, params):
        try:
            task = self.app.tasks.dismiss(args[0])
        except KeyError as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_task", "No such task.") from error
        if task is None:
            raise ApiError(HTTPStatus.CONFLICT, "task_not_failed", "Only failed tasks can be dismissed.")
        return HTTPStatus.OK, task

    def cancel_task(self, handler, operator, args, params):
        current = self.app.tasks.get(args[0])
        if current and current["kind"] == "investigate" and current["state"] == "running" and current["case"]:
            # A running step stops cooperatively: cancelling its run makes the next broker call refuse.
            self.run_write(lambda: investigate.operator_action(self.state, current["case"], "cancel", operator))
            return HTTPStatus.OK, self.app.tasks.get(args[0])
        try:
            task = self.app.tasks.cancel(args[0])
        except KeyError as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_task", "No such task.") from error
        if task is None:
            raise ApiError(HTTPStatus.CONFLICT, "task_started", "Only queued tasks can be cancelled.")
        return HTTPStatus.OK, task

    # -- lessons (Forge-wide; see re_harness/lessons.py) --

    def lessons(self, handler, operator, args, params):
        return HTTPStatus.OK, lessons.public(lessons.load(self.state))

    def set_lessons_mode(self, handler, operator, args, params):
        mode = self.body(handler).get("mode")
        try:
            lessons.set_mode(self.state, mode)
        except ValueError as error:
            raise bad("The mode is off, shadow or inject.") from error
        return HTTPStatus.OK, lessons.public(lessons.load(self.state))

    def extract_lessons(self, handler, operator, args, params):
        """Propose lessons from closed cases' reviewed outcomes. Proposed lessons are only ever shadowed."""
        touched = lessons.extract(self.state, self.visible_ids(), operator)
        return HTTPStatus.OK, {**lessons.public(lessons.load(self.state)), "touched": touched}

    def change_lesson(self, handler, operator, args, params):
        lesson_id, action = args
        if not lessons.valid_id(lesson_id) or action not in ("adopt", "retire"):
            raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "No such lesson action.")
        body = self.body(handler)
        try:
            if action == "adopt":
                row = lessons.adopt(self.state, lesson_id, operator, body.get("benchmark"))
            else:
                row = lessons.retire(self.state, lesson_id, operator)
        except KeyError as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_lesson", "No such lesson.") from error
        except ValueError as error:
            reason = str(error)
            messages = {"invalid_benchmark": "Give before and after recall and precision, each from 0 to 1.",
                        "benchmark_regressed": "Benchmarks adopt: the after run lost recall or precision.",
                        "invalid_transition": "That lesson cannot change that way."}
            status = HTTPStatus.BAD_REQUEST if reason == "invalid_benchmark" else HTTPStatus.CONFLICT
            raise ApiError(status, reason, messages.get(reason, "Refused.")) from error
        return HTTPStatus.OK, row

    # -- models --

    def model_list(self, handler, operator, args, params):
        return HTTPStatus.OK, {"models": models.listing(self.state)}

    def create_model(self, handler, operator, args, params):
        body = self.body(handler)
        try:
            return HTTPStatus.OK, models.put(self.state, body.get("id"), body, create=True)
        except models.ModelError as error:
            raise bad(str(error)) from error

    def update_model(self, handler, operator, args, params):
        try:
            return HTTPStatus.OK, models.put(self.state, args[0], self.body(handler), create=False)
        except models.ModelError as error:
            raise bad(str(error)) from error

    def delete_model(self, handler, operator, args, params):
        in_use = [case for case in case_ids(self.state) if read_settings(self.state, case)["model"] == args[0]]
        if in_use:
            raise ApiError(HTTPStatus.CONFLICT, "model_in_use", "Cases still use this model: " + ", ".join(in_use[:5]))
        try:
            models.delete(self.state, args[0])
        except models.ModelError as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_model", "No such model.") from error
        return HTTPStatus.OK, {"deleted": args[0]}

    def test_model(self, handler, operator, args, params):
        try:
            config = models.get(self.state, args[0])
        except models.ModelError as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_model", "No such model.") from error

        def job():
            try:
                return models.test(config)
            except models.ModelError as error:
                return {"ok": False, "detail": str(error)}
            except (OSError, ValueError, runtime.RuntimeFailure) as error:
                return {"ok": False, "detail": tasks.safe_error(error) if isinstance(error, runtime.RuntimeFailure)
                        else "Could not reach the model endpoint."}
        return HTTPStatus.ACCEPTED, {"task": self.app.tasks.submit("model_test", None, f"Test model {args[0]}",
                                                                   operator, job)}
