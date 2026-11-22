"""The Prometheus Forge, served over a private Unix socket to an authenticating proxy."""

import argparse
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
            _, case = runtime.load_case(state, folder.name)
        except BROWSER_ERRORS:
            continue
        rows.append((folder.name, "Paused" if case["paused"] else "Ready"))
    return rows


def baseline_tools(state):
    try:
        verified = runtime.load_baseline(state).get("verification", {})
        return (bool(verified.get("ghidra_mcp")), bool(verified.get("rea")))
    except BROWSER_ERRORS:
        return (False, False)


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

    def do_GET(self):
        if not (operator := self.identity()):
            return
        if self.path == self.server.prefix + "forge.css":
            return self.respond(HTTPStatus.OK, Path(__file__).with_name("forge.css").read_bytes(), "text/css; charset=utf-8")
        if self.path != self.server.prefix:
            return self.respond(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")
        self.dashboard(operator)

    def dashboard(self, operator, selected="", digest="", result=None, error=False):
        cases = case_rows(self.server.state, self.server.visible)
        providers = baseline_tools(self.server.state)
        rows = "".join(f'<li><span>{esc(name)}</span><span class="status">{esc(status)}</span></li>' for name, status in cases)
        if not rows:
            rows = '<li class="muted">Open a case with the Prometheus operator CLI to begin.</li>'
        options = "".join(f'<option value="{esc(name)}"{" selected" if name == selected else ""}>{esc(name)}</option>'
                          for name, status in cases if status == "Ready")
        inactive = " disabled" if not options else ""
        tools = "".join(f'<li><span>{name}</span><span class="status">{"Verified" if ready else "Awaiting baseline"}</span></li>'
                        for name, ready in zip(("Ghidra MCP", "REA"), providers))
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

    def do_POST(self):
        if not (operator := self.identity()):
            return
        if self.path != self.server.prefix + "inspect":
            return self.respond(HTTPStatus.NOT_FOUND, "Not found", "text/plain; charset=utf-8")
        if self.headers.get_all("Origin", []) != [self.server.origin]:
            return self.respond(HTTPStatus.FORBIDDEN, "Origin rejected", "text/plain; charset=utf-8")
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,3}", lengths[0]) or
                not 1 <= int(lengths[0]) <= 512 or self.headers.get("Transfer-Encoding") or
                self.headers.get_content_type() != "application/x-www-form-urlencoded"):
            return self.respond(HTTPStatus.BAD_REQUEST, "Invalid inspection form", "text/plain; charset=utf-8")
        try:
            form = parse_qs(self.rfile.read(int(lengths[0])).decode("ascii"), max_num_fields=2,
                            keep_blank_values=True, strict_parsing=True)
            if set(form) != {"case", "artifact"} or any(len(values) != 1 for values in form.values()):
                raise ValueError("invalid form")
            case_id, digest = form["case"][0], form["artifact"][0]
            values = policy.validate("artifact_summary", {"artifact": digest})
            if case_id not in {name for name, status in case_rows(self.server.state, self.server.visible) if status == "Ready"}:
                raise ValueError("case unavailable")
        except (ValueError, UnicodeError, OSError):
            return self.respond(HTTPStatus.BAD_REQUEST, "Invalid case or artifact", "text/plain; charset=utf-8")

        try:
            broker = server.Broker(self.server.state, case_id, {"artifact_summary"}, audience="forge")
            reply = broker.call({"name": "artifact_summary", "arguments": values})
            result = json.loads(reply["content"][0]["text"])
            return self.dashboard(operator, case_id, digest, result, reply["isError"])
        except BROWSER_ERRORS:
            return self.respond(HTTPStatus.SERVICE_UNAVAILABLE, "Case service unavailable", "text/plain; charset=utf-8")


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
