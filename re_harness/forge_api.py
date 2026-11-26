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

from . import accounts, cli, forge, local_model, models, policy, projection, runtime, server, tasks

JSON_LIMIT = 64 * 1024
CHAT_ROWS = 400
ROLES = tuple(local_model.ROLES)
SETTINGS_LOCK = threading.Lock()
CHAT_LOCK = threading.Lock()


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


def stamp(row, operator=None):
    return {"id": uuid.uuid4().hex, "utc": now(), **({"operator": operator} if operator else {}), **row}


# ---- Router -------------------------------------------------------------------------------------------------

class Api:
    def __init__(self, app):
        self.app = app
        self.state = app.state

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
            ("GET", ("cases", "{}", "chat")): self.chat,
            ("POST", ("cases", "{}", "chat")): self.send_chat,
            ("DELETE", ("cases", "{}", "chat")): self.clear_chat,
            ("GET", ("tasks",)): self.task_list,
            ("GET", ("tasks", "{}")): self.task,
            ("POST", ("tasks", "{}", "cancel")): self.cancel_task,
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
        if parts[0] in ("cases", "models", "tasks"):
            if len(parts) >= 2:
                return (1, 3) if len(parts) == 4 and parts[0] == "cases" and parts[2] in ("tools", "grants") else (1,)
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
            "cases": cases,
            "apprentices": [{"name": name, "verified": ok} for name, ok in forge.baseline_tools(self.state)],
            "tasks": {"queued": sum(t["state"] == "queued" for t in queue), "running": running, "recent": queue[:10]},
            "models": len(models.listing(self.state)), "audit": audit[:20]}

    def policy(self, handler, operator, args, params):
        return HTTPStatus.OK, {
            "tools": [{"name": name, "description": text, "excerpt_only": name in policy.EXCERPT_ONLY,
                       "paged": name in policy.PAGED, "addressed": name in policy.ADDRESSED,
                       "timeout_s": runtime.tool_timeout(name)} for name, text in policy.TOOLS.items()],
            "denied": ["run_ghidra_script"],
            "roles": {role: sorted(tools) for role, tools in local_model.ROLES.items()},
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

    def cancel_task(self, handler, operator, args, params):
        try:
            task = self.app.tasks.cancel(args[0])
        except KeyError as error:
            raise ApiError(HTTPStatus.NOT_FOUND, "unknown_task", "No such task.") from error
        if task is None:
            raise ApiError(HTTPStatus.CONFLICT, "task_started", "Only queued tasks can be cancelled.")
        return HTTPStatus.OK, task

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
