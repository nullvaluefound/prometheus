"""Case closure at the broker: refused sessions, refused calls and suppressed in-flight results."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import case, runtime, server

DIGEST = "a" * 64
SUMMARY = {"tool": "artifact_summary", "artifact": DIGEST, "size": 16, "format_hint": "ELF"}
CLOSED = {"closed": True, "closed_utc": "2026-11-25T10:00:00+00:00"}


class ClosedBrokerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.folder = runtime.case_path(self.state, "fixture")
        self.folder.mkdir(parents=True)
        self.scope = {"case": "fixture", "image": "sha256:" + DIGEST, "engine": "linux", "initialized": True,
                      "volume": "static-re-" + "1" * 32, "paused": False, "grants": []}
        self.save()

    def save(self, **changes):
        case.atomic_json(self.folder / "scope.json", {**self.scope, **changes})

    def events(self):
        return [json.loads(line) for line in (self.folder / "audit.jsonl").read_text().splitlines()]

    def call(self, broker):
        return broker.call({"name": "artifact_summary", "arguments": {"artifact": DIGEST}})

    def test_sessions_on_a_closed_case_are_refused_and_audited(self):
        self.save(**CLOSED)
        for audience in ("mcp", "local", "forge"):
            with self.subTest(audience=audience), self.assertRaisesRegex(runtime.RuntimeFailure, "Case is closed"):
                server.Broker(self.state, "fixture", audience=audience)
        self.assertEqual([(event["decision"], event["reason"], event["audience"]) for event in self.events()],
                         [("intercepted", "case_closed", audience) for audience in ("mcp", "local", "forge")])
        with patch.object(server.sys, "stdin") as stdin, self.assertRaisesRegex(runtime.RuntimeFailure, "closed"):
            server.serve(self.state, "fixture")
        stdin.buffer.readline.assert_not_called()

    def test_closure_mid_session_denies_calls_with_a_fixed_reason(self):
        broker = server.Broker(self.state, "fixture")
        self.save(**CLOSED)
        with patch.object(runtime, "worker") as worker:
            reply = self.call(broker)
        worker.assert_not_called()
        self.assertTrue(reply["isError"])
        self.assertEqual(json.loads(reply["content"][0]["text"]), {"status": "denied", "reason": "case_closed"})
        self.assertEqual(self.events()[-1]["reason"], "case_closed")

    def test_closure_during_dispatch_suppresses_the_result(self):
        broker = server.Broker(self.state, "fixture")

        def closing(*_args, **_kwargs):
            self.save(**CLOSED)
            return 0, json.dumps(SUMMARY).encode()

        with patch.object(runtime, "worker", side_effect=closing), \
                patch.object(server.projection, "project", return_value={"format_hint": "ELF"}) as project:
            reply = self.call(broker)
        project.assert_called_once()
        self.assertEqual(json.loads(reply["content"][0]["text"]), {"status": "denied", "reason": "case_closed"})
        self.assertEqual([event["decision"] for event in self.events()], ["dispatched", "intercepted"])


if __name__ == "__main__":
    unittest.main()
