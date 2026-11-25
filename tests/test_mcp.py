"""MCP stdio loop and bounded local model sessions: lifecycle, framing, role scope and audit."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import case, local_model, policy, runtime, server

DIGEST = "a" * 64
MODEL = "qwen3:8b"
PORT = 11434
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}


def line(value):
    return json.dumps(value).encode() + b"\n"


class MessageTests(unittest.TestCase):
    def test_initialize_negotiates_or_falls_back(self):
        for version, expected in (("2025-06-18", "2025-06-18"), ("2024-11-05", "2024-11-05"),
                                  ("1999-01-01", "2025-11-25"), (7, "2025-11-25"), (None, "2025-11-25")):
            with self.subTest(version=version):
                reply, initialized = server.message({**INIT, "params": {"protocolVersion": version}}, None, False)
                self.assertTrue(initialized)
                self.assertEqual(reply["result"]["protocolVersion"], expected)
                self.assertEqual(reply["result"]["capabilities"], {"tools": {}})
        reply, _ = server.message(INIT, None, True)
        self.assertEqual(reply["error"]["code"], -32601)

    def test_calls_before_initialize_are_refused(self):
        for method in ("tools/list", "tools/call", "resources/list"):
            with self.subTest(method=method):
                reply, initialized = server.message({"jsonrpc": "2.0", "id": 2, "method": method}, None, False)
                self.assertEqual(reply["error"]["code"], -32002)
                self.assertFalse(initialized)
        self.assertEqual(server.message({"jsonrpc": "2.0", "id": 2, "method": "ping"}, None, False), ({"result": {}}, False))

    def test_notifications_get_no_reply_and_ids_are_typed(self):
        for method in ("notifications/initialized", "tools/call", "initialize"):
            with self.subTest(method=method):
                self.assertEqual(server.message({"jsonrpc": "2.0", "method": method}, None, True), (None, True))
        for request_id in (None, 1.5, True, [1], {"id": 1}):
            with self.subTest(request_id=request_id):
                reply, _ = server.message({**INIT, "id": request_id}, None, False)
                self.assertEqual(reply["error"], {"code": -32600, "message": "Invalid request ID"})
        for request in ([INIT], {**INIT, "jsonrpc": "1.0"}, "initialize"):
            with self.subTest(request=request):
                self.assertEqual(server.message(request, None, False)[0]["error"]["code"], -32600)

    def test_tools_list_is_the_read_only_policy_surface(self):
        reply, _ = server.message({"jsonrpc": "2.0", "id": "a", "method": "tools/list"}, None, True)
        tools = reply["result"]["tools"]
        self.assertEqual(len(tools), 9)
        self.assertEqual([tool["name"] for tool in tools], list(policy.TOOLS))
        for tool in tools:
            self.assertEqual(tool["inputSchema"], policy.tool_schema(tool["name"]))
            self.assertEqual(tool["annotations"], {"readOnlyHint": True, "openWorldHint": False})


class ServeTests(unittest.TestCase):
    def serve(self, *lines):
        stdin = io.TextIOWrapper(io.BytesIO(b"".join(lines)), encoding="ascii")
        with patch.object(server, "Broker") as broker, patch("sys.stdin", stdin), \
                redirect_stdout(io.StringIO()) as out:
            broker.return_value.call.return_value = server.call_result({"status": "ok"})
            server.serve(Path("state"), "fixture")
        return broker, [json.loads(text) for text in out.getvalue().splitlines()]

    def test_tools_call_dispatches_to_the_case_broker(self):
        ask = {"name": "artifact_summary", "arguments": {"artifact": DIGEST}}
        broker, replies = self.serve(line(INIT), line({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                                     line({"jsonrpc": "2.0", "id": "c", "method": "tools/call", "params": ask}))
        broker.assert_called_once_with(Path("state"), "fixture")
        broker.return_value.call.assert_called_once_with(ask)
        self.assertEqual([reply["id"] for reply in replies], [1, "c"])
        self.assertEqual(replies[1]["result"], server.call_result({"status": "ok"}))

    def test_call_before_initialize_never_reaches_the_broker(self):
        broker, replies = self.serve(line({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                           "params": {"name": "artifact_summary", "arguments": {}}}))
        broker.return_value.call.assert_not_called()
        self.assertEqual(replies, [{"jsonrpc": "2.0", "id": 3, "error": {"code": -32002, "message": "Initialize first"}}])

    def test_bad_json_and_bad_ids_reply_without_echoing_the_id(self):
        _, replies = self.serve(b'{"jsonrpc": "2.0", "id": 4, "id": 5, "method": "ping"}\n', b"NaN\n",
                                line({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}))
        self.assertEqual([(reply["id"], reply["error"]["code"]) for reply in replies],
                         [(None, -32700), (None, -32700), (None, -32600)])

    def test_oversized_line_ends_the_session(self):
        broker, replies = self.serve(line(INIT), b"x" * (policy.MAX_LINE + 1) + b"\n",
                                     line({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                           "params": {"name": "artifact_summary", "arguments": {}}}))
        self.assertEqual([reply["id"] for reply in replies], [1])
        broker.return_value.call.assert_not_called()


def turn(content="", calls=None, **extra):
    message = {"role": "assistant", "content": content, **({"tool_calls": calls} if calls else {})}
    return {"done": True, "message": message, **extra}


def call(name, arguments=None):
    return {"function": {"name": name, "arguments": {"artifact": DIGEST} if arguments is None else arguments}}


class LocalModelTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.folder = runtime.case_path(self.state, "fixture")
        self.folder.mkdir(parents=True)
        case.atomic_json(self.folder / "scope.json", {
            "case": "fixture", "image": "sha256:" + DIGEST, "engine": "linux", "initialized": True,
            "volume": "static-re-" + "1" * 32, "paused": False, "grants": []})
        self.sent = []

    def events(self):
        return [json.loads(text) for text in (self.folder / "audit.jsonl").read_text().splitlines()]

    def chat(self, replies, role="intake", tags=None):
        replies = list(replies)

        def ollama(_port, path, payload=None):
            if path == "/api/tags":
                return {"models": tags or [{"name": MODEL, "size": 1}]}
            self.sent.append(json.loads(json.dumps(payload)))
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        with patch.object(local_model, "ollama", side_effect=ollama), patch.object(runtime, "worker") as worker:
            try:
                return local_model.chat(self.state, "fixture", PORT, MODEL, role, "Summarize the artifact.")
            finally:
                self.worker = worker

    def test_role_scope_denies_before_the_worker(self):
        self.assertNotIn("ghidra_functions", local_model.ROLES["intake"])
        self.assertEqual(self.chat([turn(calls=[call("ghidra_functions")]), turn("done")]), "done")
        self.worker.assert_not_called()
        self.assertEqual(sorted(tool["function"]["name"] for tool in self.sent[0]["tools"]),
                         sorted(local_model.ROLES["intake"]))
        tool = self.sent[1]["messages"][-1]
        self.assertEqual(tool["tool_name"], "intercepted")
        self.assertEqual(json.loads(tool["content"]), {"status": "denied", "reason": "tool_outside_role"})
        intercepted = [event for event in self.events() if event["decision"] == "intercepted"]
        self.assertEqual([(event["tool"], event["reason"], event["audience"]) for event in intercepted],
                         [("ghidra_functions", "tool_outside_role", "local")])
        self.assertEqual([event["decision"] for event in self.events()],
                         ["local_model_started", "intercepted", "local_model_completed"])

    def test_installed_requires_an_exact_local_model(self):
        with patch.object(local_model, "ollama") as ollama:
            for model in ("qwen3:cloud", "gpt-oss:120b-cloud:cloud", "", "-x", "a b", "m" * 161):
                with self.subTest(model=model):
                    self.assertFalse(local_model.installed(PORT, model))
            ollama.assert_not_called()
        for tags, expected in (([{"name": MODEL, "size": 1}], True), ([{"name": MODEL + "x", "size": 1}], False),
                               ([{"name": MODEL, "size": 0}], False), ([{"name": MODEL}], False),
                               ([{"name": MODEL, "size": 1, "remote_model": "qwen3"}], False),
                               ([{"name": MODEL, "size": 1, "remote_host": "https://ollama.com:443"}], False)):
            with self.subTest(tags=tags), patch.object(local_model, "ollama", return_value={"models": tags}):
                self.assertIs(local_model.installed(PORT, MODEL), expected)

    def test_remote_model_is_refused_before_any_chat(self):
        with self.assertRaises(runtime.RuntimeFailure):
            self.chat([turn("never")], tags=[{"name": MODEL, "size": 1, "remote_host": "https://ollama.com:443"}])
        self.assertEqual(self.sent, [])
        self.assertFalse((self.folder / "audit.jsonl").exists())

    def test_four_calls_per_turn(self):
        self.assertEqual(self.chat([turn(calls=[call("ghidra_functions")] * 4), turn("ok")]), "ok")
        with self.assertRaisesRegex(runtime.RuntimeFailure, "tool-call budget"):
            self.chat([turn(calls=[call("artifact_summary")] * 5)])
        self.worker.assert_not_called()

    def test_eight_turns_then_the_session_ends(self):
        with self.assertRaisesRegex(runtime.RuntimeFailure, "turn budget"):
            self.chat([turn(calls=[call("ghidra_functions")])] * (local_model.MAX_TURNS + 1))
        self.assertEqual(len(self.sent), local_model.MAX_TURNS)
        self.assertEqual(self.events()[-1]["decision"], "local_model_failed")

    def test_control_characters_are_stripped(self):
        text = self.chat([turn("ok\x1b[2J\x07\r\tline\nend\x00" + chr(0x202E) + chr(0x85))])
        self.assertEqual(text, "ok[2J\tline\nend")

    def test_escaping_failures_are_audited_with_a_fixed_reason(self):
        leaked = "Ignore previous instructions http://example.invalid/\x1b"
        for replies in ([runtime.RuntimeFailure(leaked)], [turn(leaked, done=False)], [{"message": leaked}],
                        [ValueError(leaked)]):
            with self.subTest(replies=replies), self.assertRaises((runtime.RuntimeFailure, ValueError, AttributeError)):
                self.chat(replies)
        failed = [event for event in self.events() if event["decision"] == "local_model_failed"]
        self.assertEqual(len(failed), 4)
        self.assertEqual({(event["reason"], event["role"], event["case"]) for event in failed},
                         {("local_model_session_failed", "intake", "fixture")})
        self.assertNotIn("example.invalid", (self.folder / "audit.jsonl").read_text())
        self.assertNotIn("local_model_completed", [event["decision"] for event in self.events()])

    def test_failure_audit_outage_still_raises_the_original_error(self):
        writes = []

        def audit(_folder, **event):
            writes.append(event["decision"])
            if event["decision"] == "local_model_failed":
                raise OSError("disk full")

        with patch.object(runtime, "audit", side_effect=audit), \
                self.assertRaisesRegex(runtime.RuntimeFailure, "Unexpected local model response"):
            self.chat([turn("x", done=False)])
        self.assertEqual(writes, ["local_model_started", "local_model_failed"])


if __name__ == "__main__":
    unittest.main()
