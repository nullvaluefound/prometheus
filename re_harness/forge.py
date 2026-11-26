"""The Prometheus Forge: a React operator app and JSON API over a private Unix socket, with its own sign-in.

A TLS proxy forwards the base path to this socket. The server renders only the sign-in, setup and account pages;
everything else is the single-page app in forge_web/ talking to the API in forge_api.py (docs/FORGE_API.md).
"""

import argparse
import collections
import datetime as dt
import html
import json
import os
import re
import socket
import socketserver
import subprocess
import threading
import time
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import accounts, cli, policy, runtime, server, tasks

BROWSER_ERRORS = (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError)
BASE_PATH = r"/(?:[a-z0-9-]+/)+"
COOKIE = "prometheus_session"
# Failed sign-ins and setup attempts across all clients. The proxy also limits each client address.
FAILURE_WINDOW = 600
FAILURE_LIMIT = 30
FORM_LIMIT = 1024  # sign-in forms stay small
WEB = Path(__file__).with_name("forge_web")
STATIC = {"assets/app.js": "text/javascript; charset=utf-8", "assets/app.css": "text/css; charset=utf-8"}
PAGE_CSP = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
APP_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
           "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


def esc(value):
    return html.escape(str(value), quote=True)


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


def recent_audit(folder, rows=AUDIT_ROWS):
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
        if len(events) == rows:
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
        if isinstance(event.get("artifact"), str) and "artifact" not in row:
            row["artifact"] = event["artifact"]
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
    if not isinstance(ledger, dict) or not isinstance(ledger.get("artifacts"), dict) or \
            not isinstance(ledger.get("findings"), list):
        raise runtime.RuntimeFailure("ledger_invalid")
    return ledger


def shell(prefix, operator, body, title="Forge"):
    prefix = esc(prefix)
    if operator:
        account = (f'<nav class="operator"><a href="{prefix}">Back to the Forge</a><a href="{prefix}account">'
                   f'{esc(operator)}</a><form class="inline" method="post" action="{prefix}logout">'
                   '<button class="link">Sign out</button></form></nav>')
    else:
        account = ""
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} · Prometheus</title><link rel="stylesheet" href="{prefix}forge.css"></head>
<body><header><div class="identity"><span class="mark" aria-hidden="true">P</span><div><strong>Prometheus</strong>
<span>Static malware analysis</span></div></div>{account}</header>
<main><h1>{esc(title)}</h1>{body}</main></body></html>'''


def notice(message, error=True):
    return f'<p class="{"error" if error else "notice"}" role="status">{esc(message)}</p>' if message else ""


class Forge(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded HTTP for the browser; Apprentice work runs one task at a time on the task queue."""

    daemon_threads = True

    def __init__(self, socket_path, origin, prefix, state, visible):
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise OSError("Serve the Forge from the Linux deployment VM")
        from . import forge_api  # forge_api imports this module
        self.address_family = socket.AF_UNIX
        self.origin = origin
        self.prefix = prefix
        self.state = state
        self.visible = visible
        self.failures = collections.deque()
        self.failure_lock = threading.Lock()
        cli.STATE = state  # the API reuses the operator CLI's case actions on this state directory
        self.tasks = tasks.TaskQueue(state)
        self.api = forge_api.Api(self)
        super().__init__(str(socket_path), Handler)

    def throttled(self):
        cutoff = time.monotonic() - FAILURE_WINDOW
        with self.failure_lock:
            while self.failures and self.failures[0] < cutoff:
                self.failures.popleft()
            return len(self.failures) >= FAILURE_LIMIT

    def record_failure(self):
        with self.failure_lock:
            self.failures.append(time.monotonic())

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(30)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    server_version = "Prometheus"
    sys_version = ""
    session_expires = None

    def log_message(self, _format, *_args):
        # The ingress owns access logging. Never log bodies or evidence in the app.
        return

    def send_common(self, csp=PAGE_CSP):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", csp)

    def respond(self, status, content, content_type="text/html; charset=utf-8", cookie=None, csp=PAGE_CSP):
        data = content.encode("utf-8") if isinstance(content, str) else content
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_common(csp)
        self.end_headers()
        self.wfile.write(data)

    def respond_json(self, status, value):
        data = json.dumps(value, ensure_ascii=True, allow_nan=False).encode("ascii")
        self.respond(status, data, "application/json")

    def redirect(self, location, cookie=None):
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_common()
        self.end_headers()

    def cookie(self, value, max_age):
        return (f"{COOKIE}={value}; Path={self.server.prefix}; Max-Age={max_age}; Secure; HttpOnly; "
                "SameSite=Strict")

    def identity(self):
        """Return the signed-in operator, or None. The proxy must not supply identity."""
        values = self.headers.get_all("Cookie", [])
        if len(values) != 1:
            return None
        try:
            jar = SimpleCookie()
            jar.load(values[0])
        except CookieError:
            return None
        if COOKIE not in jar:
            return None
        try:
            token = jar[COOKIE].value
            user = accounts.session_user(self.server.state, token)
            if user:
                self.session_expires = accounts.session_expiry(token)
            return user
        except BROWSER_ERRORS:
            return None

    def plain(self, status, message):
        self.respond(status, message, "text/plain; charset=utf-8")

    # ---- Request bodies ----

    def content_length(self, limit):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            raise ValueError("invalid framing")
        length = int(lengths[0])
        if length > limit:
            from .forge_api import ApiError
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", "The request body is too large.")
        return length

    def read_body(self, limit):
        length = self.content_length(limit)
        return self.rfile.read(length) if length else b""

    def copy_body(self, stream, limit):
        remaining = self.content_length(limit)
        if remaining == 0:
            from .forge_api import ApiError
            raise ApiError(HTTPStatus.BAD_REQUEST, "empty_upload", "The upload is empty.")
        while remaining:
            chunk = self.rfile.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("truncated upload")
            stream.write(chunk)
            remaining -= len(chunk)

    def read_form(self, fields, limit=FORM_LIMIT):
        """Parse one small urlencoded form with exactly the expected single-valued fields."""
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,4}", lengths[0]) or
                not 1 <= int(lengths[0]) <= limit or self.headers.get("Transfer-Encoding") or
                self.headers.get_content_type() != "application/x-www-form-urlencoded"):
            raise ValueError("invalid framing")
        form = parse_qs(self.rfile.read(int(lengths[0])).decode("ascii"), max_num_fields=len(fields),
                        keep_blank_values=True, strict_parsing=True, encoding="utf-8", errors="strict")
        if set(form) != set(fields) or any(len(values) != 1 for values in form.values()):
            raise ValueError("invalid form")
        return {key: values[0] for key, values in form.items()}

    # ---- Routing ----

    def do_GET(self):
        prefix = self.server.prefix
        if self.path == prefix + "forge.css":
            return self.respond(HTTPStatus.OK, Path(__file__).with_name("forge.css").read_bytes(), "text/css; charset=utf-8")
        if self.path == prefix + "login":
            return self.login_page()
        if self.path == prefix + "setup":
            return self.setup_page()
        if self.path.startswith(prefix + "api/"):
            return self.api("GET")
        if not self.path.startswith(prefix):
            return self.plain(HTTPStatus.NOT_FOUND, "Not found")
        if not (operator := self.identity()):
            return self.redirect(prefix + "login")
        if self.path == prefix:
            return self.web_file("index.html", "text/html; charset=utf-8")
        if self.path == prefix + "account":
            return self.account_page(operator)
        relative = self.path[len(prefix):]
        if relative in STATIC:
            return self.web_file(relative, STATIC[relative])
        self.plain(HTTPStatus.NOT_FOUND, "Not found")

    def web_file(self, relative, content_type):
        try:
            data = (WEB / relative).read_bytes()
        except OSError:
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "The Forge web app is not built.")
        self.respond(HTTPStatus.OK, data, content_type, csp=APP_CSP)

    def do_POST(self):
        prefix = self.server.prefix
        public = {prefix + "login": self.login, prefix + "setup": self.complete_setup}
        private = {prefix + "logout": self.logout, prefix + "account": self.change_password}
        is_api = self.path.startswith(prefix + "api/")
        if self.path not in public and self.path not in private and not is_api:
            return self.plain(HTTPStatus.NOT_FOUND, "Not found")
        # Every form and API write, sign-in included, must come from the Forge's own origin.
        if self.headers.get_all("Origin", []) != [self.server.origin]:
            return self.plain(HTTPStatus.FORBIDDEN, "Origin rejected")
        if is_api:
            return self.api("POST")
        if self.path in public:
            return public[self.path]()
        if not (operator := self.identity()):
            return self.plain(HTTPStatus.FORBIDDEN, "Sign in required")
        private[self.path](operator)

    def do_PUT(self):
        self.api_write("PUT")

    def do_DELETE(self):
        self.api_write("DELETE")

    def api_write(self, method):
        if not self.path.startswith(self.server.prefix + "api/"):
            return self.plain(HTTPStatus.NOT_FOUND, "Not found")
        if self.headers.get_all("Origin", []) != [self.server.origin]:
            return self.plain(HTTPStatus.FORBIDDEN, "Origin rejected")
        self.api(method)

    def api(self, method):
        from .forge_api import ApiError
        if not (operator := self.identity()):
            return self.respond_json(HTTPStatus.UNAUTHORIZED, {"error": "sign_in_required",
                                                               "message": "Sign in again."})
        try:
            status, value = self.server.api.dispatch(self, method, self.path[len(self.server.prefix + "api/"):],
                                                     operator)
        except ApiError as error:
            return self.respond_json(error.status, {"error": error.code, "message": error.message})
        except (ValueError, UnicodeError) as error:
            return self.respond_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request",
                                                              "message": "The request was not well formed."})
        except BROWSER_ERRORS:
            return self.respond_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "unavailable",
                                                                      "message": "The case service is unavailable."})
        self.respond_json(status, value)

    # ---- Sign-in pages ----

    def login_page(self, message="", status=HTTPStatus.OK, username=""):
        prefix = esc(self.server.prefix)
        body = f'''<section class="auth">{notice(message)}<form method="post" action="{prefix}login">
<label>Username<input name="username" value="{esc(username)}" autocomplete="username" maxlength="32" required autofocus></label>
<label>Password<input name="password" type="password" autocomplete="current-password" maxlength="72" required></label>
<button>Sign in</button></form>
<p class="muted">New account or reset? <a href="{prefix}setup">Use your one-time setup code</a>.</p></section>'''
        self.respond(status, shell(self.server.prefix, None, body, "Sign in"))

    def setup_page(self, message="", status=HTTPStatus.OK, username=""):
        prefix = esc(self.server.prefix)
        body = f'''<section class="auth">{notice(message)}
<p class="muted">An operator issues setup codes with <code>re_harness.cli forge-user</code>. Codes work once and expire after {accounts.SETUP_HOURS} hours.</p>
<form method="post" action="{prefix}setup">
<label>Username<input name="username" value="{esc(username)}" autocomplete="username" maxlength="32" required autofocus></label>
<label>Setup code<input name="code" autocomplete="one-time-code" maxlength="64" required></label>
<label>New password<input name="password" type="password" autocomplete="new-password" minlength="{accounts.MIN_PASSWORD}" maxlength="72" required></label>
<label>Confirm password<input name="confirm" type="password" autocomplete="new-password" minlength="{accounts.MIN_PASSWORD}" maxlength="72" required></label>
<button>Set password</button></form><p class="muted"><a href="{prefix}login">Back to sign in</a></p></section>'''
        self.respond(status, shell(self.server.prefix, None, body, "Set your password"))

    def account_page(self, operator, message="", error=True, status=HTTPStatus.OK):
        prefix = esc(self.server.prefix)
        body = f'''<section class="auth">{notice(message, error)}
<h2>Change password</h2><form method="post" action="{prefix}account">
<label>Current password<input name="current" type="password" autocomplete="current-password" maxlength="72" required></label>
<label>New password<input name="password" type="password" autocomplete="new-password" minlength="{accounts.MIN_PASSWORD}" maxlength="72" required></label>
<label>Confirm new password<input name="confirm" type="password" autocomplete="new-password" minlength="{accounts.MIN_PASSWORD}" maxlength="72" required></label>
<button>Change password</button></form>
<p class="muted">Use at least {accounts.MIN_PASSWORD} characters. Changing your password signs out your other sessions.</p></section>'''
        self.respond(status, shell(self.server.prefix, operator, body, "Account"))

    def login(self):
        if self.server.throttled():
            return self.login_page("Too many failed attempts. Try again in a few minutes.", HTTPStatus.TOO_MANY_REQUESTS)
        try:
            form = self.read_form(("username", "password"))
        except (ValueError, UnicodeError, OSError):
            return self.plain(HTTPStatus.BAD_REQUEST, "Invalid sign-in form")
        username = form["username"].strip().lower()
        try:
            epoch = accounts.authenticate(self.server.state, username, form["password"])
            token = accounts.issue_session(self.server.state, username, epoch) if epoch is not None else None
        except BROWSER_ERRORS:
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "Account service unavailable")
        if token is None:
            self.server.record_failure()
            return self.login_page("The username or password is not correct.", HTTPStatus.UNAUTHORIZED,
                                   username if accounts.valid_username(username) else "")
        self.redirect(self.server.prefix, self.cookie(token, accounts.SESSION_HOURS * 3600))

    def complete_setup(self):  # never name this setup(): BaseRequestHandler calls setup() to open the socket
        if self.server.throttled():
            return self.setup_page("Too many failed attempts. Try again in a few minutes.", HTTPStatus.TOO_MANY_REQUESTS)
        try:
            form = self.read_form(("username", "code", "password", "confirm"))
        except (ValueError, UnicodeError, OSError):
            return self.plain(HTTPStatus.BAD_REQUEST, "Invalid setup form")
        username = form["username"].strip().lower()
        shown = username if accounts.valid_username(username) else ""
        if form["password"] != form["confirm"]:
            return self.setup_page("The passwords do not match.", HTTPStatus.BAD_REQUEST, shown)
        try:
            epoch = accounts.complete_setup(self.server.state, username, form["code"].strip(), form["password"])
            token = accounts.issue_session(self.server.state, username, epoch)
        except accounts.AccountError as error:
            if "setup code" in str(error):
                self.server.record_failure()
            return self.setup_page(str(error), HTTPStatus.BAD_REQUEST, shown)
        except BROWSER_ERRORS:
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "Account service unavailable")
        self.redirect(self.server.prefix, self.cookie(token, accounts.SESSION_HOURS * 3600))

    def logout(self, operator):
        """End every session of this operator. The form carries no fields, so the body is never read."""
        try:
            accounts.end_sessions(self.server.state, operator)
        except BROWSER_ERRORS:
            pass
        self.redirect(self.server.prefix + "login", self.cookie("", 0))

    def change_password(self, operator):
        try:
            form = self.read_form(("current", "password", "confirm"))
        except (ValueError, UnicodeError, OSError):
            return self.plain(HTTPStatus.BAD_REQUEST, "Invalid password form")
        if form["password"] != form["confirm"]:
            return self.account_page(operator, "The new passwords do not match.", status=HTTPStatus.BAD_REQUEST)
        try:
            epoch = accounts.change_password(self.server.state, operator, form["current"], form["password"])
            token = accounts.issue_session(self.server.state, operator, epoch)
        except accounts.AccountError as error:
            return self.account_page(operator, str(error), status=HTTPStatus.BAD_REQUEST)
        except BROWSER_ERRORS:
            return self.plain(HTTPStatus.SERVICE_UNAVAILABLE, "Account service unavailable")
        content = shell(self.server.prefix, operator, '<section class="auth">' +
                        notice("Password changed. Other sessions are signed out.", False) + '</section>', "Account")
        self.respond(HTTPStatus.OK, content, cookie=self.cookie(token, accounts.SESSION_HOURS * 3600))


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
