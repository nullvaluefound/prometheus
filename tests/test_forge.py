import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from re_harness import forge, runtime
from re_harness.case import atomic_json


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class ForgeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        state = Path(directory.name)
        self.digest = "a" * 64
        case_dir = runtime.case_path(state, "review")
        case_dir.mkdir(parents=True)
        image = "sha256:" + self.digest
        atomic_json(case_dir / "scope.json", {"case": "review", "engine": "linux", "image": image,
                     "volume": "static-re-" + "1" * 32, "paused": False, "grants": [], "initialized": True})
        atomic_json(state / "baseline.json", {"engine": "linux", "image": image,
                    "verification": {"ghidra_mcp": "fixture", "rea": "fixture"}})
        self.path = state / "forge.sock"
        self.origin = "https://forge.example"
        self.app = forge.Forge(self.path, self.origin, "/prometheus/", state, {"review"})
        self.addCleanup(self.app.server_close)
        thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.app.shutdown)

    def request(self, method, route, headers=None, form=None):
        client = UnixHTTP(str(self.path), timeout=4)
        try:
            client.request(method, route, headers=headers or {}, body=urlencode(form) if form else None)
            response = client.getresponse()
            return response.status, response.read().decode("utf-8"), dict(response.headers)
        finally:
            client.close()

    def test_identity_and_rendering(self):
        self.assertEqual(self.request("GET", "/prometheus/")[0], 403)
        status, body, headers = self.request("GET", "/prometheus/", {"X-Forge-Operator": "analyst"})
        self.assertEqual(status, 200)
        for text in ("Prometheus", "Forge", "Apprentices", "review", "Verified"):
            self.assertIn(text, body)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("GET", "/prometheus/../forge.py", {"X-Forge-Operator": "analyst"})[0], 404)

    def test_inspection_is_origin_and_case_bound(self):
        headers = {"X-Forge-Operator": "analyst", "Origin": self.origin,
                   "Content-Type": "application/x-www-form-urlencoded"}
        form = {"case": "review", "artifact": self.digest}
        with patch.object(forge.server, "Broker") as broker:
            self.assertEqual(self.request("POST", "/prometheus/inspect", {**headers, "Origin": "https://else.example"}, form)[0], 403)
            self.assertEqual(self.request("POST", "/prometheus/inspect", headers, {**form, "case": "other"})[0], 400)
            self.assertEqual(self.request("POST", "/prometheus/inspect", headers, {**form, "tool": "anything"})[0], 400)
            broker.assert_not_called()
            broker.return_value.call.return_value = {"content": [{"text": json.dumps({"format_hint": "ELF"})}],
                                                       "isError": False}
            status, body, _ = self.request("POST", "/prometheus/inspect", headers, form)
            self.assertEqual(status, 200)
            self.assertIn("ELF", body)
            self.assertEqual(broker.call_args.args[-1], {"artifact_summary"})
            self.assertEqual(broker.call_args.kwargs, {"audience": "forge"})
            broker.return_value.call.assert_called_once_with({"name": "artifact_summary", "arguments": {"artifact": self.digest}})
