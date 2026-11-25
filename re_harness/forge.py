"""The Prometheus Forge, served over a private Unix socket to an authenticating proxy."""

import argparse
import datetime as dt
import html
import json
import os
import re
import socket
import socketserver
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import policy, runtime, server
from .case import atomic_json

BROWSER_ERRORS = (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError)
OPERATOR = r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}"
BASE_PATH = r"/(?:[a-z0-9-]+/)+"


def esc(value):
    return html.escape(str(value), quote=True)


def case_rows(state, visible):
    root = state / "cases"
    if not root.is_dir():
        return []
    rows = []
    for folder in sorted(root.iterdir(), key=lambda item: item.name):
        if len(rows) == 100:
            break
        if folder.is_symlink() or not policy.match(folder.name, policy.CASE_ID):
            continue
        if visible and folder.name not in visible:
            continue
        try:
            _, case = runtime.load_case(state, folder.name, allow_closed=True)
        except BROWSER_ERRORS:
            continue
        rows.append((folder.name, case_status(case)))
    return rows


def case_status(record):
    return "Closed" if runtime.closed(record) else "Paused" if record["paused"] else "Ready"


APPRENTICES = (("ghidra_mcp", "Ghidra MCP"), ("rea", "REA"), ("yara", "YARA"), ("capa", "capa"))


def baseline_tools(state):
    """Return (label, verified) for each baseline Apprentice the selftest records."""
    try:
        verified = runtime.load_baseline(state).get("verification", {})
        if not isinstance(verified, dict):
            verified = {}
    except BROWSER_ERRORS:
        verified = {}
    return tuple((label, bool(verified.get(key))) for key, label in APPRENTICES)


AUDIT_TAIL = 256 * 1024
AUDIT_ROWS = 50
AUDIT_FIELDS = ("utc", "decision", "tool", "audience", "reason", "operation", "operator", "via")
LEDGER_CAP = 4 * 1024 * 1024


def recent_audit(folder):
    """Return the newest audit events, newest first, keeping only display-safe fields."""
    path = folder / "audit.jsonl"
    try:
        with path.open("rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            stream.seek(max(0, size - AUDIT_TAIL))
            data = stream.read(AUDIT_TAIL)
    except OSError:
        return []
    lines = data.split(b"\n")
    if size > AUDIT_TAIL:
        lines = lines[1:]
    events = []
    for line in reversed(lines):
        if len(events) == AUDIT_ROWS:
            break
        try:
            event = json.loads(line.decode("ascii"))
        except (UnicodeError, ValueError):
            continue
        if not isinstance(event, dict):
            continue
        row = {key: event[key] for key in AUDIT_FIELDS if isinstance(event.get(key), (str, bool))}
        arguments = event.get("arguments")
        grant = event.get("grant")
        if isinstance(grant, dict):  # CLI grant events nest the grant record
            arguments = grant.get("arguments")
            for key in ("tool", "audience"):
                if isinstance(grant.get(key), str):
                    row[key] = grant[key]
        elif isinstance(grant, str):  # revoke events carry the grant ID
            row["reason"] = "grant " + grant[:8]
        if isinstance(arguments, dict):
            for key in ("artifact", "address"):
                if isinstance(arguments.get(key), str):
                    row[key] = arguments[key]
        events.append(row)
    return events


def active_grants(record, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    grants = []
    for grant in record["grants"]:
        try:
            if dt.datetime.fromisoformat(grant["expires_utc"]) > now:
                grants.append(grant)
        except (KeyError, TypeError, ValueError):
            continue
    return grants


def case_ledger(record):
    """Read the evidence ledger through a read-only Apprentice. It holds operator metadata, not sample bytes."""
    code, data = runtime.worker(record, ["case", "status"], cap=LEDGER_CAP, timeout=60)
    if code:
        raise runtime.RuntimeFailure("ledger_unavailable")
    ledger = server.strict_json(data)
    if not isinstance(ledger, dict) or not isinstance(ledger.get("artifacts"), dict) or             not isinstance(ledger.get("findings"), list):
        raise runtime.RuntimeFailure("ledger_invalid")
    return ledger


def pause_case(state, case_id, operator):
    """One-way browser control. Resume, grants and intake stay with the operator CLI."""
    folder = runtime.case_path(state, case_id)
    with runtime.operator_lock(folder):
        _, record = runtime.load_case(state, case_id)
        if record["paused"]:
            return False
        record["paused"] = True
        runtime.audit(folder, case=case_id, decision="pause", operator=operator, via="forge")
        atomic_json(folder / "scope.json", record)
    return True


def text(value):
    return esc(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ""


def table(headings, rows, empty):
    if not rows:
        return f'<p class="muted">{esc(empty)}</p>'
    head = "".join(f"<th>{esc(name)}</th>" for name in headings)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def shell(prefix, operator, body):
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forge · Prometheus</title><link rel="stylesheet" href="{esc(prefix)}forge.css"></head>
<body><header><div class="identity"><span class="mark" aria-hidden="true">P</span><div><strong>Prometheus</strong>
<span>Static malware analysis</span></div></div><span class="operator">{esc(operator)}</span></header>
<main><h1>Forge</h1>{body}</main></body></html>'''


class Forge(socketserver.TCPServer):
    """Serve one request at a time to keep browser-triggered Docker work bounded."""

    def __init__(self, socket_path, origin, prefix, state, visible):
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise OSError("Serve the Forge from the Linux deployment VM")
        self.address_family = socket.AF_UNIX
        self.origin = origin
        self.prefix = prefix
        self.state = state
        self.visible = visible
        super().__init__(str(socket_path), Handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(8)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    server_version = "Prometheus"
    sys_version = ""

    def log_message(self, _format, *_args):
        # The ingress owns access logging. Never log bodies or evidence in the app.
        return

    def respond(self, status, content, content_type="text/html; charset=utf-8"):
        data = content.encode("utf-8") if isinstance(content, str) else content
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def identity(self):
        values = self.headers.get_all("X-Forge-Operator", [])
        if len(values) == 1 and policy.match(values[0], OPERATOR):
            return values[0]
        self.respond(HTTPStatus.FORBIDDEN, "Authenticated ingress required", "text/plain; charset=utf-8")
        return None

    def plain(self, status, message):
        self.respond(status, message, "text/plain; charset=utf-8")

    def listed_cases(self):
        return {name: status for name, status in case_rows(self.server.state, self.server.visible)}

    def do_GET(self):
        if not (operator := self.identity()):
            return
        prefix = self.server.prefix
        if self.path == prefix + "forge.css":
            return self.respond(HTTPStatus.OK, Path(__file__).with_name("forge.css").read_bytes(), "text/css; charset=utf-8")
        if self.path == prefix:
            return self.dashboard(operator)
        if self.path.startswith(prefix + "cases/"):
            case_id = self.path[len(prefix + "cases/"):]
            if policy.match(case_id, policy.CASE_ID) and case_id in self.listed_cases():
                return self.case_page(operator, case_id)
        self.plain(HTTPStatus.NOT_FOUND, "Not found")

    def case_link(self, name):
        return f'<a href="{esc(self.server.prefix)}cases/{esc(name)}">{esc(name)}</a>'

    def dashboard(self, operator, selected="", digest="", result=None, error=False):
        cases = case_rows(self.server.state, self.server.visible)
        providers = baseline_tools(self.server.state)
        rows = "".join(f'<li><span>{self.case_link(name)}</span><span class="status">{esc(status)}</span></li>'
                       for name, status in cases)
        if not rows:
            rows = '<li class="muted">Open a case with the Prometheus operator CLI to begin.</li>'
        options = "".join(f'<option value="{esc(name)}"{" selected" if name == selected else ""}>{esc(name)}</option>'
                          for name, status in cases if status == "Ready")
        inactive = " disabled" if not options else ""
        tools = "".join(f'<li><span>{esc(name)}</span><span class="status">{"Verified" if ready else "Awaiting baseline"}</span></li>'
                        for name, ready in providers)
        output = ""
        if result is not None:
            rendered = esc(json.dumps(result, indent=2, ensure_ascii=True))
            output = f'<section class="result"><h2>{"Inspection stopped" if error else "Artifact summary"}</h2><pre>{rendered}</pre></section>'
        body = f'''<div class="layout"><section><h2>Cases</h2><ul>{rows}</ul></section>
<section><h2>Apprentices</h2><ul>{tools}</ul></section></div>
<section class="inspect"><h2>Inspect an artifact</h2><form method="post" action="{esc(self.server.prefix)}inspect">
<label>Case<select name="case" required{inactive}>{options}</select></label>
<label>SHA-256<input name="artifact" value="{esc(digest)}" pattern="[a-f0-9]{{64}}" maxlength="64" required{inactive}></label>
<button{inactive}>Inspect</button></form></section>{output}'''
        self.respond(HTTPStatus.OK, shell(self.server.prefix, operator, body))

    def case_page(self, operator, case_id):
        try:
            folder, record = runtime.load_case(self.server.state, case_id, allow_closed=True)
        except BROWSER_ERRORS:
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "Case service unavailable")
        prefix = esc(self.server.prefix)
        status = case_status(record)
        paused = status != "Ready"
        hidden_case = f'<input type="hidden" name="case" value="{esc(case_id)}">'
        if status == "Closed":
            control = (f'<p class="muted">Closed {text(record.get("closed_utc"))}. Closure is irreversible. '
                       'The ledger, report and evidence volume are retained read-only.</p>')
        elif paused:
            control = '<p class="muted">Paused. Resume with the operator CLI after reviewing scope.</p>'
        else:
            control = (f'<form class="inline" method="post" action="{prefix}pause">{hidden_case}'
                       '<button class="stop">Pause case</button></form>'
                       '<p class="muted">Pausing closes new broker actions at once. Only the operator CLI can resume.</p>')
        rules = record.get("yara_rules")
        yara_rules = (f'<code>{esc(rules["sha256"])}</code>' if rules else '<span class="muted">None imported</span>')
        scope = (f'<ul><li><span>Status</span><span class="status">{esc(status)}</span></li>'
                 f'<li><span>Image</span><code>{esc(record["image"])}</code></li>'
                 f'<li><span>Engine</span><code>{esc(record["engine"])}</code></li>'
                 f'<li><span>YARA rules</span>{yara_rules}</li></ul>{control}')

        try:
            ledger = case_ledger(record)
        except BROWSER_ERRORS:
            ledger = None
        if ledger is None:
            unavailable = '<p class="muted">The evidence ledger is unavailable. Check the Docker engine and run verify.</p>'
            ledger_html, artifacts_html, findings_html = unavailable, unavailable, unavailable
        else:
            ledger_html = f'<p>{text(ledger.get("title"))}</p><p class="muted">{len(ledger["artifacts"])} artifacts · ' \
                          f'{len(ledger["findings"])} findings</p>'
            artifacts = []
            for digest, item in sorted(ledger["artifacts"].items())[:256]:
                if not policy.match(digest, policy.DIGEST) or not isinstance(item, dict):
                    continue
                provenance = item.get("provenance") if isinstance(item.get("provenance"), list) else []
                origin = "<br>".join(
                    f'{text(entry.get("source"))} · {text(entry.get("completeness"))}'
                    + (f'<br><span class="muted">from <code>{text(entry.get("parent"))}</code> '
                       f'({text(entry.get("relation"))})</span>' if entry.get("parent") else "")
                    for entry in provenance[:4] if isinstance(entry, dict))
                summary = "" if status == "Closed" else (
                    f'<form class="inline" method="post" action="{prefix}inspect">{hidden_case}'
                    f'<input type="hidden" name="artifact" value="{esc(digest)}">'
                    f'<button{" disabled" if paused else ""}>Summary</button></form>')
                artifacts.append((f"<code>{esc(digest)}</code>", text(item.get("size")), origin, summary))
            artifacts_html = table(("SHA-256", "Bytes", "Provenance", ""), artifacts, "No artifacts admitted yet.")
            findings = []
            for item in ledger["findings"][:200]:
                if not isinstance(item, dict):
                    continue
                cited = item.get("artifacts") if isinstance(item.get("artifacts"), list) else []
                evidence = item.get("evidence") if isinstance(item.get("evidence"), list) else []
                findings.append((text(item.get("id")), text(item.get("kind")), text(item.get("confidence")),
                                 text(item.get("claim")), "<br>".join(text(value) for value in evidence[:8]),
                                 "<br>".join(f"<code>{text(value)}</code>" for value in cited[:8])))
            findings_html = table(("ID", "Kind", "Confidence", "Claim", "Evidence", "Artifacts"), findings,
                                  "No findings recorded yet.")

        grants = []
        for grant in active_grants(record):
            arguments = grant.get("arguments")
            if not isinstance(arguments, dict):
                continue
            selector = " ".join(f"{key}={value}" for key, value in sorted(arguments.items()) if key != "artifact")
            grants.append((f'<code>{text(grant.get("id"))[:8]}</code>', text(grant.get("tool")),
                           f'<code>{text(arguments.get("artifact"))}</code>', text(selector),
                           text(grant.get("audience")), text(grant.get("expires_utc"))))
        grants_html = table(("Grant", "Tool", "Artifact", "Selector", "Audience", "Expires (UTC)"), grants,
                            "No active excerpt grants.")
        events = [(text(event.get("utc")), text(event.get("decision")),
                   text(event.get("tool") or event.get("operation")), text(event.get("audience") or event.get("via")),
                   text(event.get("reason") or event.get("operator") or event.get("address")),
                   f'<code>{text(event["artifact"])}</code>' if event.get("artifact") else "")
                  for event in recent_audit(folder)]
        audit_html = table(("UTC", "Decision", "Tool or operation", "Audience", "Detail", "Artifact"), events,
                           "No audit events yet.")
        body = f'''<p class="crumb"><a href="{prefix}">Forge</a> / {esc(case_id)}</p>
<div class="layout"><section><h2>Ledger</h2>{ledger_html}</section><section><h2>Scope</h2>{scope}</section></div>
<section class="block"><h2>Artifacts</h2>{artifacts_html}</section>
<section class="block"><h2>Findings</h2>{findings_html}</section>
<section class="block"><h2>Active grants</h2>{grants_html}</section>
<section class="block"><h2>Recent audit</h2>{audit_html}</section>'''
        self.respond(HTTPStatus.OK, shell(self.server.prefix, operator, body))

    def read_form(self, fields):
        """Parse one small urlencoded form with exactly the expected single-valued fields."""
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,3}", lengths[0]) or
                not 1 <= int(lengths[0]) <= 512 or self.headers.get("Transfer-Encoding") or
                self.headers.get_content_type() != "application/x-www-form-urlencoded"):
            raise ValueError("invalid framing")
        form = parse_qs(self.rfile.read(int(lengths[0])).decode("ascii"), max_num_fields=len(fields),
                        keep_blank_values=True, strict_parsing=True)
        if set(form) != set(fields) or any(len(values) != 1 for values in form.values()):
            raise ValueError("invalid form")
        return {key: values[0] for key, values in form.items()}

    def do_POST(self):
        if not (operator := self.identity()):
            return
        routes = {self.server.prefix + "inspect": self.inspect, self.server.prefix + "pause": self.pause}
        if self.path not in routes:
            return self.plain(HTTPStatus.NOT_FOUND, "Not found")
        if self.headers.get_all("Origin", []) != [self.server.origin]:
            return self.plain(HTTPStatus.FORBIDDEN, "Origin rejected")
        routes[self.path](operator)

    def inspect(self, operator):
        try:
            form = self.read_form(("case", "artifact"))
            case_id, digest = form["case"], form["artifact"]
            values = policy.validate("artifact_summary", {"artifact": digest})
            status = self.listed_cases().get(case_id)
        except (ValueError, UnicodeError, OSError):
            return self.plain(HTTPStatus.BAD_REQUEST, "Invalid case or artifact")
        if status == "Closed":
            return self.plain(HTTPStatus.CONFLICT, "Case is closed")
        if status != "Ready":
            return self.plain(HTTPStatus.BAD_REQUEST, "Invalid case or artifact")
        try:
            broker = server.Broker(self.server.state, case_id, {"artifact_summary"}, audience="forge")
            reply = broker.call({"name": "artifact_summary", "arguments": values})
            result = json.loads(reply["content"][0]["text"])
            return self.dashboard(operator, case_id, digest, result, reply["isError"])
        except BROWSER_ERRORS:
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "Case service unavailable")

    def pause(self, operator):
        try:
            case_id = self.read_form(("case",))["case"]
            if not policy.match(case_id, policy.CASE_ID) or case_id not in (listed := self.listed_cases()):
                raise ValueError("case unavailable")
        except (ValueError, UnicodeError, OSError):
            return self.plain(HTTPStatus.BAD_REQUEST, "Invalid case")
        if listed[case_id] == "Closed":
            return self.plain(HTTPStatus.CONFLICT, "Case is closed")
        try:
            pause_case(self.server.state, case_id, operator)
        except runtime.RuntimeFailure as error:
            if "lock" in str(error):
                return self.plain(HTTPStatus.CONFLICT, "Another operator command holds this case. Pause from the CLI.")
            if "closed" in str(error):
                return self.plain(HTTPStatus.CONFLICT, "Case is closed")
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "Case service unavailable")
        except BROWSER_ERRORS:
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "Case service unavailable")
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"{self.server.prefix}cases/{case_id}")
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--origin", required=True, help="Public HTTPS origin, with no trailing slash")
    parser.add_argument("--prefix", default="/prometheus/")
    parser.add_argument("--case", action="append", default=[], help="Limit visibility to this case. Repeat as needed.")
    options = parser.parse_args()
    origin = urlsplit(options.origin)
    if (not policy.match(options.prefix, BASE_PATH) or origin.scheme != "https" or not origin.hostname or
            origin.username is not None or origin.password is not None or origin.path or origin.query or origin.fragment or
            any(not policy.match(case, policy.CASE_ID) for case in options.case)):
        parser.error("Provide a valid HTTPS origin, base path and optional case IDs")
    if not options.socket.is_absolute():
        parser.error("The Unix socket must use an absolute path in a private runtime directory")
    os.umask(0o077)
    with Forge(options.socket, options.origin, options.prefix, runtime.STATE, set(options.case)) as app:
        options.socket.chmod(0o660)
        try:
            app.serve_forever()
        finally:
            options.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
