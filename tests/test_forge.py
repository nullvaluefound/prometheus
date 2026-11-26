import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import accounts, forge
from re_harness.case import atomic_json
from tests.forge_support import FORM_TYPE, ForgeServer


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class ForgeTests(ForgeServer, unittest.TestCase):
    def setUp(self):
        self.start_forge()

    def test_app_shell_is_served_only_to_a_session(self):
        status, _, headers = self.request("GET", "/prometheus/")
        self.assertEqual((status, headers["Location"]), (303, "/prometheus/login"))
        status, body, headers = self.request("GET", "/prometheus/", self.operator)
        self.assertEqual(status, 200)
        self.assertIn('<div id="root">', body)
        csp = headers["Content-Security-Policy"]
        for directive in ("default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"):
            self.assertIn(directive, csp)
        self.assertNotIn("unsafe", csp)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        status, body, headers = self.request("GET", "/prometheus/assets/app.js", self.operator)
        self.assertEqual((status, body), (200, "console.log('forge')"))
        self.assertTrue(headers["Content-Type"].startswith("text/javascript"))
        self.assertEqual(self.request("GET", "/prometheus/assets/app.js")[0], 303)
        for route in ("/prometheus/../forge.py", "/prometheus/assets/../forge.py", "/prometheus/assets/other.js",
                      "/prometheus/index.html"):
            with self.subTest(route=route):
                self.assertEqual(self.request("GET", route, self.operator)[0], 404)

    def test_missing_build_is_reported_not_crashed(self):
        with patch.object(forge, "WEB", self.state / "absent"):
            status, body, _ = self.request("GET", "/prometheus/", self.operator)
        self.assertEqual((status, body), (503, "The Forge web app is not built."))

    def test_identity_comes_only_from_a_valid_session(self):
        body, mac = self.token.split(".")
        for headers in ({"X-Forge-Operator": "analyst"}, {"Cookie": "prometheus_session="},
                        {"Cookie": "prometheus_session=" + body + ".AAAA"},
                        {"Cookie": "prometheus_session=" + body[:-2] + "xx." + mac},
                        {"Cookie": "other=" + self.token}, {"Cookie": "prometheus_session=\"unterminated"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("GET", "/prometheus/", headers)[0], 303)
                self.assertEqual(self.request("GET", "/prometheus/api/me", headers)[0], 401)
        duplicated = (b"GET /prometheus/ HTTP/1.1\r\nHost: forge\r\nCookie: " + self.cookie + b"\r\n"
                      b"Cookie: " + self.cookie + b"\r\nConnection: close\r\n\r\n")
        self.assertEqual(self.raw(duplicated), 303)
        self.assertEqual(self.request("POST", "/prometheus/api/cases/review/pause", {"Origin": self.origin})[0], 401)

    def test_stylesheet_and_unknown_routes(self):
        status, body, headers = self.request("GET", "/prometheus/forge.css")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/css"))
        self.assertEqual(body, (Path(forge.__file__).with_name("forge.css")).read_text(encoding="utf-8"))
        self.assertEqual(self.request("GET", "/elsewhere/", self.operator)[0], 404)
        self.assertEqual(self.request("POST", "/prometheus/other", self.post_headers, {"a": "b"})[0], 404)
        self.assertEqual(self.request("PUT", "/prometheus/login", self.writes)[0], 404)

    def test_every_write_requires_the_forge_origin(self):
        for method, route in (("POST", "/prometheus/api/cases/review/pause"), ("PUT", "/prometheus/api/models/x"),
                              ("DELETE", "/prometheus/api/cases/review/chat"), ("POST", "/prometheus/logout")):
            for origin in ({}, {"Origin": "https://else.example"}):
                with self.subTest(route=route, origin=origin):
                    self.assertEqual(self.request(method, route, {**self.operator, **origin})[0], 403)
        self.assertFalse(json.loads((self.state / "cases" / "review" / "scope.json").read_text())["paused"])

    def sign_in(self, username, password, origin=None):
        headers = {"Origin": origin or self.origin, "Content-Type": FORM_TYPE}
        return self.request("POST", "/prometheus/login", headers, {"username": username, "password": password})

    def session_of(self, headers):
        value = headers["Set-Cookie"].split(";")[0]
        self.assertTrue(value.startswith("prometheus_session="))
        return {"Cookie": value}

    def test_sign_in_sets_a_hardened_session_cookie(self):
        status, body, _ = self.request("GET", "/prometheus/login")
        self.assertEqual(status, 200)
        self.assertIn('action="/prometheus/login"', body)
        status, _, headers = self.sign_in("Analyst", "correct horse battery")
        self.assertEqual((status, headers["Location"]), (303, "/prometheus/"))
        flags = [part.strip() for part in headers["Set-Cookie"].split(";")[1:]]
        for flag in ("Path=/prometheus/", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=43200"):
            self.assertIn(flag, flags)
        session = self.session_of(headers)
        self.assertEqual(self.request("GET", "/prometheus/", session)[0], 200)
        status, body, _ = self.request("GET", "/prometheus/api/me", session)
        self.assertEqual(json.loads(body)["user"], "analyst")

    def test_failed_sign_in_reveals_nothing_and_is_throttled(self):
        for username, password in (("analyst", "wrong password!"), ("nobody", "correct horse battery"),
                                   ("../etc", "x"), ("analyst", "")):
            with self.subTest(username=username):
                status, body, headers = self.sign_in(username, password)
                self.assertEqual(status, 401)
                self.assertIn("The username or password is not correct.", body)
                self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(self.sign_in("analyst", "correct horse battery", "https://else.example")[0], 403)
        self.app.failures.extend([forge.time.monotonic()] * forge.FAILURE_LIMIT)
        self.assertEqual(self.sign_in("analyst", "correct horse battery")[0], 429)

    def test_setup_code_sets_the_first_password_once(self):
        code = accounts.issue_setup(self.state, "newcomer")
        form = {"username": "newcomer", "code": code, "password": "a long new passphrase", "confirm": "a long new passphrase"}
        headers = {"Origin": self.origin, "Content-Type": FORM_TYPE}
        self.assertEqual(self.sign_in("newcomer", "a long new passphrase")[0], 401)
        mismatch = self.request("POST", "/prometheus/setup", headers, {**form, "confirm": "something else entirely"})
        self.assertEqual(mismatch[0], 400)
        self.assertIn("do not match", mismatch[1])
        short = self.request("POST", "/prometheus/setup", headers, {**form, "password": "short", "confirm": "short"})
        self.assertIn("at least 12 characters", short[1])
        wrong = self.request("POST", "/prometheus/setup", headers, {**form, "code": "not-the-code"})
        self.assertIn("not valid", wrong[1])
        status, _, response = self.request("POST", "/prometheus/setup", headers, form)
        self.assertEqual(status, 303)
        self.assertEqual(self.request("GET", "/prometheus/", self.session_of(response))[0], 200)
        self.assertEqual(self.request("POST", "/prometheus/setup", headers, form)[0], 400)
        self.assertEqual(self.sign_in("newcomer", "a long new passphrase")[0], 303)

    def test_password_change_requires_the_current_password_and_ends_other_sessions(self):
        form = {"current": "wrong password!", "password": "a brand new secret", "confirm": "a brand new secret"}
        status, body, _ = self.request("POST", "/prometheus/account", self.post_headers, form)
        self.assertEqual(status, 400)
        self.assertIn("current password is not correct", body)
        status, body, headers = self.request("POST", "/prometheus/account", self.post_headers,
                                             {**form, "current": "correct horse battery"})
        self.assertEqual(status, 200)
        self.assertIn("Password changed", body)
        self.assertEqual(self.request("GET", "/prometheus/", self.operator)[0], 303)
        self.assertEqual(self.request("GET", "/prometheus/account", self.session_of(headers))[0], 200)
        self.assertEqual(self.sign_in("analyst", "correct horse battery")[0], 401)
        self.assertEqual(self.sign_in("analyst", "a brand new secret")[0], 303)

    def test_sign_out_ends_the_session(self):
        status, _, headers = self.request("POST", "/prometheus/logout", {**self.operator, "Origin": self.origin})
        self.assertEqual((status, headers["Location"]), (303, "/prometheus/login"))
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.request("GET", "/prometheus/", self.operator)[0], 303)

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
