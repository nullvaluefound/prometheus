"""A Forge served on a temporary Unix socket, with a signed-in operator, for the Forge test modules."""

import http.client
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
from unittest.mock import patch
from urllib.parse import urlencode

from re_harness import accounts, forge, runtime
from re_harness.case import atomic_json

FORM_TYPE = "application/x-www-form-urlencoded"


def write_case(state, case_id, image, paused=False, initialized=True):
    case_dir = runtime.case_path(state, case_id)
    case_dir.mkdir(parents=True)
    atomic_json(case_dir / "scope.json", {"case": case_id, "engine": "linux", "image": image,
                "volume": "static-re-" + "1" * 32, "paused": paused, "grants": [], "initialized": initialized})


class ForgeServer:
    """Mixin for unittest.TestCase classes. Call start_forge() from setUp."""

    def start_forge(self, visible=("review", "frozen")):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = state = Path(directory.name)
        self.digest = "a" * 64
        self.image = "sha256:" + self.digest
        write_case(state, "review", self.image)
        write_case(state, "frozen", self.image, paused=True)
        write_case(state, "offscope", self.image)
        atomic_json(state / "baseline.json", {"engine": "linux", "image": self.image,
                    "verification": {"ghidra_mcp": "fixture", "rea": "fixture", "yara": "fixture",
                                     "capa": "fixture"}})
        web = state / "web"
        (web / "assets").mkdir(parents=True)
        (web / "index.html").write_text('<!doctype html><div id="root"></div><script src="./assets/app.js"></script>',
                                        encoding="ascii")
        (web / "assets" / "app.js").write_text("console.log('forge')", encoding="ascii")
        (web / "assets" / "app.css").write_text("body{}", encoding="ascii")
        for patcher in (patch.object(forge, "WEB", web), patch.dict(accounts.SCRYPT, {"n": 2 ** 10})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.path = state / "forge.sock"
        self.origin = "https://forge.example"
        self.app = forge.Forge(self.path, self.origin, "/prometheus/", state, set(visible))
        self.addCleanup(self.app.server_close)
        thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.app.shutdown)
        code = accounts.issue_setup(state, "analyst")
        epoch = accounts.complete_setup(state, "analyst", code, "correct horse battery")
        self.token = accounts.issue_session(state, "analyst", epoch)
        self.cookie = ("prometheus_session=" + self.token).encode("ascii")
        self.operator = {"Cookie": self.cookie.decode("ascii")}
        self.post_headers = {**self.operator, "Origin": self.origin, "Content-Type": FORM_TYPE}
        self.writes = {**self.operator, "Origin": self.origin}

    def request(self, method, route, headers=None, form=None, body=None):
        if form is not None:
            body = urlencode(form).encode("ascii")
        body = body or b""
        lines = [f"{method} {route} HTTP/1.1", "Host: forge", "Connection: close"]
        lines += [f"{name}: {value}" for name, value in (headers or {}).items()]
        if form is not None or body:
            lines.append(f"Content-Length: {len(body)}")
        return self.exchange(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body)

    def api(self, method, route, value=None, headers=None, raw=None, content_type="application/json"):
        headers = dict(self.writes if method != "GET" else self.operator) if headers is None else headers
        body = raw if raw is not None else (json.dumps(value).encode("ascii") if value is not None else None)
        if body is not None:
            headers["Content-Type"] = content_type
        elif method != "GET":
            body = b""
            headers["Content-Length"] = "0"
        status, text, response_headers = self.request(method, "/prometheus/api/" + route, headers, body=body)
        try:
            return status, json.loads(text) if text else None
        except ValueError:
            return status, text

    def wait(self, task):
        for _ in range(200):
            status, current = self.api("GET", f"tasks/{task['id']}")
            if current["state"] not in ("queued", "running"):
                return current
            time.sleep(0.02)
        raise AssertionError("task did not finish")

    def raw(self, data):
        """Send hand-built bytes so header duplication and framing can be tested."""
        return self.exchange(data)[0]

    def exchange(self, data):
        # The Forge rejects bad requests before reading their bodies, so a request split across
        # writes can race the server's close. One write mirrors the buffering NGINX proxy does.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(6)
            sock.connect(str(self.path))
            sock.sendall(data)
            response = http.client.HTTPResponse(sock)
            response.begin()
            return response.status, response.read().decode("utf-8"), dict(response.headers)
