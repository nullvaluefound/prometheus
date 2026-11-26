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

OPERATOR = {"X-Forge-Operator": "analyst"}
FORM_TYPE = "application/x-www-form-urlencoded"


def write_case(state, case_id, image, paused=False):
    case_dir = runtime.case_path(state, case_id)
    case_dir.mkdir(parents=True)
    atomic_json(case_dir / "scope.json", {"case": case_id, "engine": "linux", "image": image,
                "volume": "static-re-" + "1" * 32, "paused": paused, "grants": [], "initialized": True})


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class ForgeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = state = Path(directory.name)
        self.digest = "a" * 64
        image = "sha256:" + self.digest
        write_case(state, "review", image)
        write_case(state, "frozen", image, paused=True)
        write_case(state, "offscope", image)
        atomic_json(state / "baseline.json", {"engine": "linux", "image": image,
                    "verification": {"ghidra_mcp": "fixture", "rea": "fixture", "yara": "fixture",
                                     "capa": "fixture"}})
        self.path = state / "forge.sock"
        self.origin = "https://forge.example"
        self.app = forge.Forge(self.path, self.origin, "/prometheus/", state, {"review", "frozen"})
        self.addCleanup(self.app.server_close)
        thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.app.shutdown)
        self.form = {"case": "review", "artifact": self.digest}
        self.post_headers = {**OPERATOR, "Origin": self.origin, "Content-Type": FORM_TYPE}

    def request(self, method, route, headers=None, form=None):
        body = urlencode(form).encode("ascii") if form else b""
        lines = [f"{method} {route} HTTP/1.1", "Host: forge", "Connection: close"]
        lines += [f"{name}: {value}" for name, value in (headers or {}).items()]
        if form:
            lines.append(f"Content-Length: {len(body)}")
        return self.exchange(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body)

    def raw(self, data):
        """Send hand-built bytes so header duplication and framing can be tested."""
        return self.exchange(data)[0]

    def exchange(self, data):
        # The Forge rejects bad requests before reading their bodies, so a request split across
        # writes can race the server's close. One write mirrors the buffering NGINX proxy does.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect(str(self.path))
            sock.sendall(data)
            response = http.client.HTTPResponse(sock)
            response.begin()
            return response.status, response.read().decode("utf-8"), dict(response.headers)

    def test_identity_and_rendering(self):
        self.assertEqual(self.request("GET", "/prometheus/")[0], 403)
        status, body, headers = self.request("GET", "/prometheus/", OPERATOR)
        self.assertEqual(status, 200)
        for text in ("Prometheus", "Forge", "Apprentices", "review", "Verified"):
            self.assertIn(text, body)
        for label in ("Ghidra MCP", "REA", "YARA", "capa"):
            self.assertIn(f'<li><span>{label}</span><span class="status">Verified</span></li>', body)
        self.assertNotIn("Awaiting baseline", body)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.request("GET", "/prometheus/../forge.py", OPERATOR)[0], 404)

    def test_operator_identity_must_be_single_and_well_formed(self):
        for value in ("", "-leading", "has space", "a" * 65, "semi;colon"):
            with self.subTest(value=value):
                self.assertEqual(self.request("GET", "/prometheus/", {"X-Forge-Operator": value})[0], 403)
        duplicated = (b"GET /prometheus/ HTTP/1.1\r\nHost: forge\r\nX-Forge-Operator: analyst\r\n"
                      b"X-Forge-Operator: root\r\nConnection: close\r\n\r\n")
        self.assertEqual(self.raw(duplicated), 403)

    def test_stylesheet_and_unknown_routes(self):
        status, body, headers = self.request("GET", "/prometheus/forge.css", OPERATOR)
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/css"))
        self.assertEqual(body, (Path(forge.__file__).with_name("forge.css")).read_text(encoding="utf-8"))
        self.assertEqual(self.request("GET", "/prometheus/forge.css", {})[0], 403)
        self.assertEqual(self.request("GET", "/elsewhere/", OPERATOR)[0], 404)
        self.assertEqual(self.request("POST", "/prometheus/other", self.post_headers, self.form)[0], 404)

    def test_case_visibility_and_pause_state(self):
        _, body, _ = self.request("GET", "/prometheus/", OPERATOR)
        self.assertIn("frozen", body)
        self.assertIn("Paused", body)
        self.assertNotIn("offscope", body)
        self.assertIn('<option value="review">', body)
        self.assertNotIn('<option value="frozen"', body)
        with patch.object(forge.server, "Broker") as broker:
            for case_id in ("frozen", "offscope"):
                with self.subTest(case=case_id):
                    status = self.request("POST", "/prometheus/inspect", self.post_headers,
                                          {**self.form, "case": case_id})[0]
                    self.assertEqual(status, 400)
            broker.assert_not_called()

    def test_inspection_is_origin_and_case_bound(self):
        headers, form = self.post_headers, self.form
        with patch.object(forge.server, "Broker") as broker:
            self.assertEqual(self.request("POST", "/prometheus/inspect", {**headers, "Origin": "https://else.example"}, form)[0], 403)
            missing_origin = {key: value for key, value in headers.items() if key != "Origin"}
            self.assertEqual(self.request("POST", "/prometheus/inspect", missing_origin, form)[0], 403)
            self.assertEqual(self.request("POST", "/prometheus/inspect", headers, {**form, "case": "other"})[0], 400)
            self.assertEqual(self.request("POST", "/prometheus/inspect", headers, {**form, "tool": "anything"})[0], 400)
            self.assertEqual(self.request("POST", "/prometheus/inspect", headers, {**form, "artifact": "../input.bin"})[0], 400)
            broker.assert_not_called()
            broker.return_value.call.return_value = {"content": [{"text": json.dumps({"format_hint": "ELF"})}],
                                                       "isError": False}
            status, body, _ = self.request("POST", "/prometheus/inspect", headers, form)
            self.assertEqual(status, 200)
            self.assertIn("ELF", body)
            self.assertIn("Artifact summary", body)
            self.assertEqual(broker.call_args.args[-1], {"artifact_summary"})
            self.assertEqual(broker.call_args.kwargs, {"audience": "forge"})
            broker.return_value.call.assert_called_once_with({"name": "artifact_summary", "arguments": {"artifact": self.digest}})

    def test_inspection_form_framing(self):
        with patch.object(forge.server, "Broker") as broker:
            json_type = {**self.post_headers, "Content-Type": "application/json"}
            self.assertEqual(self.request("POST", "/prometheus/inspect", json_type, self.form)[0], 400)
            oversized = {**self.form, "artifact": self.digest + "a" * 600}
            self.assertEqual(self.request("POST", "/prometheus/inspect", self.post_headers, oversized)[0], 400)
            body = urlencode(self.form).encode("ascii")
            chunked = (b"POST /prometheus/inspect HTTP/1.1\r\nHost: forge\r\nX-Forge-Operator: analyst\r\n"
                       b"Origin: " + self.origin.encode("ascii") + b"\r\nContent-Type: " + FORM_TYPE.encode("ascii") +
                       b"\r\nContent-Length: " + str(len(body)).encode("ascii") +
                       b"\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + body)
            self.assertEqual(self.raw(chunked), 400)
            doubled = (b"POST /prometheus/inspect HTTP/1.1\r\nHost: forge\r\nX-Forge-Operator: analyst\r\n"
                       b"Origin: " + self.origin.encode("ascii") + b"\r\nContent-Type: " + FORM_TYPE.encode("ascii") +
                       b"\r\nContent-Length: " + str(len(body)).encode("ascii") +
                       b"\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + body)
            self.assertEqual(self.raw(doubled), 400)
            repeated = self.request("POST", "/prometheus/inspect", self.post_headers,
                                    [("case", "review"), ("case", "review"), ("artifact", self.digest)])
            self.assertEqual(repeated[0], 400)
            broker.assert_not_called()

    def test_provider_output_is_escaped_and_errors_are_contained(self):
        with patch.object(forge.server, "Broker") as broker:
            hostile = {"format_hint": "<script>alert(1)</script>"}
            broker.return_value.call.return_value = {"content": [{"text": json.dumps(hostile)}], "isError": True}
            status, body, _ = self.request("POST", "/prometheus/inspect", self.post_headers, self.form)
            self.assertEqual(status, 200)
            self.assertIn("Inspection stopped", body)
            self.assertNotIn("<script>", body)
            self.assertIn("&lt;script&gt;", body)
            broker.return_value.call.side_effect = RuntimeError("worker failed")
            status, body, _ = self.request("POST", "/prometheus/inspect", self.post_headers, self.form)
            self.assertEqual(status, 503)
            self.assertNotIn("worker failed", body)


    def ledger(self):
        hostile = "<img src=x onerror=alert(1)>"
        return {"title": "Review " + hostile, "mode": "static", "findings": [
                    {"id": "F0001", "kind": "inferred", "confidence": "medium", "claim": "Claim " + hostile,
                     "evidence": ["RVA 0x5120"], "artifacts": [self.digest]}],
                "artifacts": {self.digest: {"size": 16, "hashes": {}, "provenance": [
                    {"source": "Operator handoff " + hostile, "completeness": "complete", "parent": None,
                     "relation": "", "acquired_utc": "2026-11-25T00:00:00+00:00"}]},
                    "not-a-digest": {"size": 1}}}

    def add_grants_and_audit(self):
        folder = runtime.case_path(self.state, "review")
        scope = runtime.read_json(folder / "scope.json")
        scope["grants"] = [
            {"id": "b" * 32, "tool": "ghidra_decompile", "arguments": {"artifact": self.digest, "address": "0x401000"},
             "audience": "local", "expires_utc": "2999-01-01T00:00:00+00:00"},
            {"id": "c" * 32, "tool": "artifact_strings", "arguments": {"artifact": self.digest, "offset": 0, "limit": 10},
             "audience": "mcp", "expires_utc": "2000-01-01T00:00:00+00:00"}]
        atomic_json(folder / "scope.json", scope)
        runtime.audit(folder, case="review", decision="intercepted", tool="ghidra_decompile", audience="mcp",
                      reason="operator_excerpt_grant_required", prompt="secret model prompt",
                      arguments={"artifact": self.digest, "address": "0x401000"})

    def test_case_page_renders_scope_ledger_grants_and_audit(self):
        _, body, _ = self.request("GET", "/prometheus/", OPERATOR)
        self.assertIn('<a href="/prometheus/cases/review">review</a>', body)
        self.add_grants_and_audit()
        with patch.object(forge, "case_ledger", return_value=self.ledger()) as ledger:
            status, body, headers = self.request("GET", "/prometheus/cases/review", OPERATOR)
        self.assertEqual(status, 200)
        self.assertEqual(ledger.call_args.args[0]["case"], "review")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("<img", body)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", body)
        for expected in ("F0001", "RVA 0x5120", "Operator handoff", "Pause case", "bbbbbbbb", "0x401000",
                         "operator_excerpt_grant_required", 'name="artifact" value="' + self.digest + '"'):
            self.assertIn(expected, body)
        self.assertNotIn("cccccccc", body)
        self.assertNotIn("not-a-digest", body)
        self.assertNotIn("secret model prompt", body)

    def test_case_page_degrades_without_ledger_and_hides_unlisted_cases(self):
        with patch.object(forge, "case_ledger", side_effect=runtime.RuntimeFailure("ledger_unavailable")):
            status, body, _ = self.request("GET", "/prometheus/cases/review", OPERATOR)
        self.assertEqual(status, 200)
        self.assertIn("evidence ledger is unavailable", body)
        self.assertIn("None imported", body)
        folder, record = runtime.load_case(self.state, "review")
        atomic_json(folder / "scope.json", {**record, "yara_rules": {"sha256": "d" * 64, "rules": 3, "bytes": 90}})
        with patch.object(forge, "case_ledger", return_value=None):
            self.assertIn("<code>" + "d" * 64 + "</code>", self.request("GET", "/prometheus/cases/review", OPERATOR)[1])
        with patch.object(forge, "case_ledger") as ledger:
            for route in ("/prometheus/cases/offscope", "/prometheus/cases/missing", "/prometheus/cases/../review",
                          "/prometheus/cases/Review", "/prometheus/cases/", "/prometheus/cases/review/"):
                with self.subTest(route=route):
                    self.assertEqual(self.request("GET", route, OPERATOR)[0], 404)
            self.assertEqual(self.request("GET", "/prometheus/cases/review", {})[0], 403)
            ledger.assert_not_called()

    def test_pause_is_one_way_audited_and_origin_bound(self):
        folder = runtime.case_path(self.state, "review")
        paused = lambda: runtime.read_json(folder / "scope.json")["paused"]
        form = {"case": "review"}
        self.assertEqual(self.request("POST", "/prometheus/pause", {**self.post_headers, "Origin": "https://else.example"}, form)[0], 403)
        self.assertEqual(self.request("POST", "/prometheus/pause", self.post_headers, {"case": "offscope"})[0], 400)
        self.assertEqual(self.request("POST", "/prometheus/pause", self.post_headers, {**form, "resume": "1"})[0], 400)
        self.assertEqual(self.request("POST", "/prometheus/resume", self.post_headers, form)[0], 404)
        self.assertFalse(paused())
        status, _, headers = self.request("POST", "/prometheus/pause", self.post_headers, form)
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/prometheus/cases/review")
        self.assertTrue(paused())
        events = [json.loads(line) for line in (folder / "audit.jsonl").read_text(encoding="ascii").splitlines()]
        self.assertEqual([(e["decision"], e["operator"], e["via"]) for e in events], [("pause", "analyst", "forge")])
        self.assertEqual(self.request("POST", "/prometheus/pause", self.post_headers, form)[0], 303)
        self.assertEqual(len((folder / "audit.jsonl").read_text(encoding="ascii").splitlines()), 1)
        with patch.object(forge, "case_ledger", return_value=self.ledger()):
            _, body, _ = self.request("GET", "/prometheus/cases/review", OPERATOR)
        self.assertNotIn("Pause case", body)
        self.assertIn("Resume with the operator CLI", body)
        self.assertEqual(self.request("POST", "/prometheus/inspect", self.post_headers, self.form)[0], 400)

    def test_closed_case_is_read_only(self):
        write_case(self.state, "sealed", "sha256:" + self.digest)
        folder = runtime.case_path(self.state, "sealed")
        atomic_json(folder / "scope.json", {**runtime.read_json(folder / "scope.json"), "closed": True,
                                            "closed_utc": "2026-11-25T10:00:00+00:00"})
        before = (folder / "scope.json").read_bytes()
        self.app.visible.add("sealed")
        _, body, _ = self.request("GET", "/prometheus/", OPERATOR)
        self.assertIn('<a href="/prometheus/cases/sealed">sealed</a></span><span class="status">Closed</span>', body)
        self.assertNotIn('<option value="sealed"', body)
        with patch.object(forge, "case_ledger", return_value=self.ledger()):
            status, body, _ = self.request("GET", "/prometheus/cases/sealed", OPERATOR)
        self.assertEqual(status, 200)
        for expected in ('<span class="status">Closed</span>', "Closure is irreversible", "2026-11-25T10:00:00+00:00",
                         "F0001", self.digest):
            self.assertIn(expected, body)
        for hidden in ("Pause case", 'action="/prometheus/pause"', 'action="/prometheus/inspect"', "Summary"):
            self.assertNotIn(hidden, body)
        with patch.object(forge.server, "Broker") as broker:
            for route, form in (("/prometheus/inspect", {**self.form, "case": "sealed"}),
                                ("/prometheus/pause", {"case": "sealed"})):
                with self.subTest(route=route):
                    status, body, _ = self.request("POST", route, self.post_headers, form)
                    self.assertEqual((status, body), (409, "Case is closed"))
            broker.assert_not_called()
        self.assertEqual((folder / "scope.json").read_bytes(), before)
        self.assertFalse((folder / "audit.jsonl").exists())
        with self.assertRaisesRegex(runtime.RuntimeFailure, "Case is closed"):
            forge.pause_case(self.state, "sealed", "analyst")

    def test_pause_respects_operator_lock(self):
        lock = runtime.case_path(self.state, "review") / ".operator.lock"
        lock.write_text("1", encoding="ascii")
        self.assertEqual(self.request("POST", "/prometheus/pause", self.post_headers, {"case": "review"})[0], 409)
        self.assertFalse(runtime.read_json(lock.parent / "scope.json")["paused"])


class ForgeHelperTests(unittest.TestCase):
    def test_recent_audit_is_bounded_newest_first_and_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            lines = [json.dumps({"utc": f"t{index:04}", "decision": "completed", "prompt": "hidden",
                                 "arguments": {"artifact": "a" * 64, "offset": 3}}) for index in range(5000)]
            (folder / "audit.jsonl").write_text("\n".join(lines) + "\nnot json\n[1]\n", encoding="ascii")
            events = forge.recent_audit(folder)
            self.assertEqual(len(events), forge.AUDIT_ROWS)
            self.assertEqual(events[0]["utc"], "t4999")
            self.assertEqual(events[0], {"utc": "t4999", "decision": "completed", "artifact": "a" * 64})
            self.assertEqual(forge.recent_audit(folder / "missing"), [])
            (folder / "audit.jsonl").write_text(
                json.dumps({"utc": "t1", "decision": "grant", "grant": {
                    "id": "d" * 32, "tool": "ghidra_decompile", "audience": "mcp",
                    "arguments": {"artifact": "a" * 64, "address": "0x10"}}}) + "\n" +
                json.dumps({"utc": "t2", "decision": "revoke", "grant": "d" * 32}) + "\n", encoding="ascii")
            revoke, grant = forge.recent_audit(folder)
            self.assertEqual(grant, {"utc": "t1", "decision": "grant", "tool": "ghidra_decompile", "audience": "mcp",
                                     "artifact": "a" * 64, "address": "0x10"})
            self.assertEqual(revoke, {"utc": "t2", "decision": "revoke", "reason": "grant dddddddd"})

    def test_active_grants_skip_expired_and_malformed(self):
        record = {"grants": [{"expires_utc": "2999-01-01T00:00:00+00:00", "id": "keep"},
                             {"expires_utc": "2000-01-01T00:00:00+00:00", "id": "old"},
                             {"expires_utc": "soon", "id": "bad"}, {"id": "none"}]}
        self.assertEqual([grant["id"] for grant in forge.active_grants(record)], ["keep"])


class ForgeArgumentTests(unittest.TestCase):
    """Command-line validation runs before any socket exists, so it is checked on every platform."""

    def reject(self, *args):
        argv = ["forge", "--socket", str(Path(tempfile.gettempdir()).resolve() / "forge.sock"), *args]
        with patch("sys.argv", argv), patch.object(forge, "Forge") as app, \
                patch("sys.stderr"), self.assertRaises(SystemExit):
            forge.main()
        app.assert_not_called()

    def test_rejects_unsafe_origin_prefix_and_cases(self):
        for args in (["--origin", "http://forge.example"],
                     ["--origin", "https://forge.example/"],
                     ["--origin", "https://user:pass@forge.example"],
                     ["--origin", "https://forge.example?x=1"],
                     ["--origin", "https://"],
                     ["--origin", "https://forge.example", "--prefix", "prometheus/"],
                     ["--origin", "https://forge.example", "--prefix", "/Prometheus/"],
                     ["--origin", "https://forge.example", "--prefix", "/../"],
                     ["--origin", "https://forge.example", "--case", "../escape"]):
            with self.subTest(args=args):
                self.reject(*args)

    def test_rejects_relative_socket(self):
        with patch("sys.argv", ["forge", "--socket", "forge.sock", "--origin", "https://forge.example"]), \
                patch.object(forge, "Forge") as app, patch("sys.stderr"), self.assertRaises(SystemExit):
            forge.main()
        app.assert_not_called()

    def test_refuses_to_serve_without_unix_sockets(self):
        if os.name == "posix":
            self.skipTest("Unix sockets are available")
        with self.assertRaises(OSError):
            forge.Forge(Path("forge.sock"), "https://forge.example", "/prometheus/", Path("."), set())


class BaselineToolsTests(unittest.TestCase):
    def baseline(self, verification):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        state = Path(directory.name)
        record = {"engine": "linux", "image": "sha256:" + "a" * 64}
        if verification is not None:
            record["verification"] = verification
        atomic_json(state / "baseline.json", record)
        return state

    def test_reports_each_selftest_apprentice(self):
        state = self.baseline({"ghidra_mcp": "ok", "rea": "ok", "yara": "", "capa": "ok"})
        self.assertEqual(forge.baseline_tools(state),
                         (("Ghidra MCP", True), ("REA", True), ("YARA", False), ("capa", True)))

    def test_missing_or_invalid_baseline_awaits_every_apprentice(self):
        expected = (("Ghidra MCP", False), ("REA", False), ("YARA", False), ("capa", False))
        self.assertEqual(forge.baseline_tools(self.baseline(None)), expected)
        self.assertEqual(forge.baseline_tools(self.baseline(["ghidra_mcp"])), expected)
        empty = tempfile.TemporaryDirectory()
        self.addCleanup(empty.cleanup)
        self.assertEqual(forge.baseline_tools(Path(empty.name)), expected)


if __name__ == "__main__":
    unittest.main()
