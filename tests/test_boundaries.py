import datetime as dt
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from re_harness import case, decoding, policy, projection, runtime, server

DIGEST = "a" * 64
SCHEMA_ARGS = {"artifact": DIGEST, "address": "0x1000"}
SUMMARY = {"tool": "artifact_summary", "artifact": DIGEST, "artifact_bytes": 16,
           "summary": {"size": 16, "format_hint": "unknown", "strings_count": 1, "strings_truncated": False}}


class InputTests(unittest.TestCase):
    def test_closed_schema_and_normalization(self):
        self.assertEqual(policy.validate("ghidra_decompile", {**SCHEMA_ARGS, "address": "0x001000"}), SCHEMA_ARGS)
        for name, args in [("emulate_function", SCHEMA_ARGS), ("ghidra_decompile", {**SCHEMA_ARGS, "path": "a"}),
                           ("artifact_summary", {"artifact": "../input.bin"}),
                           ("artifact_strings", {"artifact": DIGEST, "limit": True})]:
            with self.subTest(name=name, args=args), self.assertRaises(policy.Denied):
                policy.validate(name, args)

    def test_json_duplicate_and_nonfinite_values(self):
        for data in ('{"key":1,"key":2}', '{"limit":NaN}'):
            with self.assertRaises(ValueError):
                server.strict_json(data)

    def test_bounded_host_output(self):
        cmd = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'a' * 8192)"]
        with self.assertRaises(runtime.RuntimeFailure):
            runtime.capped_run(cmd, subprocess.DEVNULL, None, subprocess.DEVNULL, 3, 1024)

    def test_projection_rejects_provider_text_in_metadata(self):
        self.assertEqual(projection.project(SUMMARY, "artifact_summary", {"artifact": DIGEST}, False), SUMMARY)
        for payload in ({**SUMMARY, "explanation": "unexpected"},
                        {**SUMMARY, "summary": {**SUMMARY["summary"], "format_hint": "arbitrary text"}}):
            with self.assertRaises(ValueError):
                projection.project(payload, "artifact_summary", {"artifact": DIGEST}, False)

    def test_bounded_decode_and_single_stream(self):
        data = gzip.compress(b"safe fixture")
        self.assertEqual(decoding.decode("gzip", data), b"safe fixture")
        for source in (data[:-1], data + data):
            with self.assertRaises(ValueError):
                decoding.decode("gzip", source)
        with patch.object(decoding, "OUTPUT_CAP", 5), self.assertRaises(ValueError):
            decoding.decode("gzip", data)

    def test_report_defangs_mixed_case_scheme(self):
        self.assertEqual(case.defang("HtTpS://example.invalid"), "hxxps://example.invalid")


class BrokerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.folder = runtime.case_path(self.state, "fixture")
        self.folder.mkdir(parents=True)
        self.scope = {"case": "fixture", "image": "sha256:" + DIGEST, "engine": "linux", "initialized": True,
                      "volume": "static-re-" + "1" * 32, "paused": False, "grants": []}
        self.save()

    def save(self):
        case.atomic_json(self.folder / "scope.json", self.scope)

    def grant(self, audience):
        self.scope["grants"] = [{"tool": "ghidra_decompile", "arguments": SCHEMA_ARGS, "audience": audience,
                                "expires_utc": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2)).isoformat()}]
        self.save()

    def test_denial_precedes_worker(self):
        broker = server.Broker(self.state, "fixture")
        with patch.object(runtime, "worker") as worker:
            self.assertTrue(broker.call({"name": "debugger_attach", "arguments": SCHEMA_ARGS})["isError"])
            self.assertTrue(broker.call({"name": "ghidra_decompile", "arguments": SCHEMA_ARGS})["isError"])
            self.scope["paused"] = True
            self.save()
            self.assertTrue(broker.call({"name": "artifact_summary", "arguments": {"artifact": DIGEST}})["isError"])
            worker.assert_not_called()

    def test_audience_and_revocation_during_analysis(self):
        self.grant("local")
        mcp = server.Broker(self.state, "fixture")
        local = server.Broker(self.state, "fixture", audience="local")
        ask = {"name": "ghidra_decompile", "arguments": SCHEMA_ARGS}
        sample = {"tool": "ghidra_decompile", "artifact": DIGEST, "artifact_bytes": 16,
                  "summary": {"provider_response": "structured", "top_level_fields": 1},
                  "evidence_excerpt": {"trust": "untrusted_sample_derived_data", "text": "fixture",
                                       "sha256_of_serialized_result": DIGEST, "serialized_bytes": 7, "truncated": False}}

        def revoked(*_args, **_kwargs):
            self.scope["grants"] = []
            self.save()
            return 0, json.dumps(sample).encode()

        with patch.object(runtime, "worker", return_value=(0, json.dumps(sample).encode())) as worker:
            self.assertTrue(mcp.call(ask)["isError"])
            worker.assert_not_called()
            self.assertFalse(local.call(ask)["isError"])
        with patch.object(runtime, "worker", side_effect=revoked):
            self.assertTrue(local.call(ask)["isError"])

    def test_audit_failure_blocks_dispatch(self):
        broker = server.Broker(self.state, "fixture")
        with patch.object(runtime, "worker") as worker, patch.object(runtime, "audit", side_effect=OSError):
            self.assertTrue(broker.call({"name": "artifact_summary", "arguments": {"artifact": DIGEST}})["isError"])
            worker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
