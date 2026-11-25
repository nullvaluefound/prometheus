"""Offline worker entry point on the host: request contract, artifact integrity, export, derive and limits."""

import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from re_harness import case, policy, providers, worker

SAMPLE = b"\x7fELF" + b"\x00" * 16 + b" visible_marker_text " + b"\x00" * 8
RULES = b'rule a { condition: true }\n'


class WorkerCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve() / "case"
        (self.root / "artifacts").mkdir(parents=True)
        self.ledger = {"schema_version": 1, "title": "fixture", "created_utc": case.now(), "mode": "static",
                       "artifacts": {}, "findings": []}
        for name, value in (("ROOT", self.root), ("YARA_RULES", self.root / "rules" / "yara.yar")):
            patcher = patch.object(worker, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.digest = self.add(SAMPLE)

    def add(self, data):
        digest = hashlib.sha256(data).hexdigest()
        path = self.root / "artifacts" / (digest + ".bin")
        path.write_bytes(data)
        size, identities = case.hashes(path)
        self.ledger["artifacts"][digest] = {"size": size, "hashes": identities, "provenance": []}
        self.save()
        return digest

    def save(self):
        case.atomic_json(self.root / "case.json", self.ledger)

    def request(self, tool="artifact_summary", excerpt=False, **arguments):
        return {"tool": tool, "arguments": {"artifact": self.digest, **arguments}, "excerpt": excerpt}

    def refused(self, error, call, *args):
        with self.assertRaises(ValueError) as caught:
            call(*args)
        self.assertEqual(str(caught.exception), error)


class AnalyzeTests(WorkerCase):
    def test_request_keys_are_closed(self):
        base = self.request()
        for request in ({**base, "rules": "b" * 64}, {**base, "full": True},
                        {key: base[key] for key in ("tool", "arguments")}, {**base, "excerpt": 1},
                        {**base, "excerpt": None}, self.request("yara_scan")):
            with self.subTest(request=request):
                self.refused("invalid_worker_request", worker.analyze, request)

    def test_policy_rejects_arguments(self):
        for request in (self.request("emulate"), self.request(path="/etc/passwd"),
                        {**self.request(), "arguments": {"artifact": "../case.json"}}):
            with self.subTest(request=request), self.assertRaises(policy.Denied):
                worker.analyze(request)

    def test_excerpt_only_tools_need_grant_before_provider(self):
        for name in sorted(policy.EXCERPT_ONLY):
            with self.subTest(name=name), patch.object(providers, "run") as run:
                self.refused("excerpt_grant_required", worker.analyze, self.request(name, address="0x10"))
                run.assert_not_called()
        with patch.object(providers, "run", return_value={"code": "int main()"}) as run:
            result = worker.analyze(self.request("ghidra_decompile", True, address="0x0010"))
        self.assertEqual(run.call_args.args[2], {"address": "0x10"})
        self.assertEqual(result["summary"], {"provider_response": "structured", "top_level_fields": 1})
        self.assertIn("int main()", result["evidence_excerpt"]["text"])
        self.assertEqual(result["evidence_excerpt"]["trust"], "untrusted_sample_derived_data")

    def test_summary_is_metadata_only(self):
        result = worker.analyze(self.request())
        self.assertEqual(result["artifact_bytes"], len(SAMPLE))
        self.assertEqual(result["summary"]["format_hint"], "ELF")
        self.assertNotIn("evidence_excerpt", result)

    def test_strings_rows_have_no_text(self):
        result = worker.analyze(self.request("artifact_strings"))
        self.assertEqual(result["summary"]["rows"], [{"offset": 20, "encoding": "ascii", "full_byte_length": 21}])
        self.assertNotIn("visible_marker_text", json.dumps(result))
        granted = worker.analyze(self.request("artifact_strings", True))
        self.assertNotIn("visible_marker_text", json.dumps(granted["summary"]))
        self.assertIn("visible_marker_text", granted["evidence_excerpt"]["text"])
        captured = worker.analyze(self.request("artifact_strings"), full=True)
        self.assertNotIn("evidence_excerpt", captured)
        self.assertEqual(captured["evidence"]["result"][0]["text"], " visible_marker_text ")

    def test_yara_scan_binds_case_rules(self):
        self.refused("yara_rules_missing", worker.analyze, {**self.request("yara_scan"), "rules": "b" * 64})
        worker.YARA_RULES.parent.mkdir()
        worker.YARA_RULES.write_bytes(RULES)
        digest = hashlib.sha256(RULES).hexdigest()
        with patch.object(providers, "yara_scan", return_value=({"rows": []}, None)) as scan:
            result = worker.analyze({**self.request("yara_scan"), "rules": digest})
        self.assertEqual(scan.call_args.args[:2], (worker.YARA_RULES, self.root / "artifacts" / (self.digest + ".bin")))
        self.assertEqual(result["summary"], {"rows": [], "rules_sha256": digest})


class ArtifactTests(WorkerCase):
    def test_intact_artifact(self):
        path, size, identities = worker.artifact(self.digest)
        self.assertEqual((path.read_bytes(), size, identities["sha256"]), (SAMPLE, len(SAMPLE), self.digest))

    def test_unknown_or_malformed_digest(self):
        for digest in ("b" * 64, self.digest.upper(), "../case.json"):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                worker.artifact(digest)

    def test_tampered_bytes(self):
        path = self.root / "artifacts" / (self.digest + ".bin")
        path.write_bytes(SAMPLE[:-1] + b"!")
        self.refused("artifact_integrity", worker.artifact, self.digest)

    def test_tampered_size_record(self):
        self.ledger["artifacts"][self.digest]["size"] += 1
        self.save()
        self.refused("artifact_integrity", worker.artifact, self.digest)

    def test_type_and_size_limits(self):
        with patch.object(policy, "MAX_ARTIFACT", len(SAMPLE) - 1):
            self.refused("artifact_type_or_size", worker.artifact, self.digest)
        path = self.root / "artifacts" / (self.digest + ".bin")
        path.unlink()
        path.mkdir()
        self.refused("artifact_type_or_size", worker.artifact, self.digest)

    def test_unsupported_ledger(self):
        self.ledger["schema_version"] = 2
        self.save()
        with self.assertRaises(ValueError):
            worker.artifact(self.digest)


class ExportTests(WorkerCase):
    def export(self, name):
        stream = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(worker.sys, "stdout", stream):
            worker.export_file(name)
        return stream.buffer.getvalue()

    def symlink(self, link, target, directory=False):
        try:
            os.symlink(target, link, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable to this user")

    def test_allowed_names(self):
        self.assertEqual(self.export(self.digest), SAMPLE)
        self.assertEqual(json.loads(self.export("case.json"))["title"], "fixture")
        (self.root / "analysis").mkdir()
        (self.root / "analysis" / (self.digest + ".triage.json")).write_bytes(b"{}")
        self.assertEqual(self.export(self.digest + ".triage.json"), b"{}")

    def test_names_are_closed(self):
        self.refused("artifact_digest_required", self.export, "artifact")
        for name in ("../x", "/etc/passwd", "artifacts/" + self.digest + ".bin", "scope.json", "rules/yara.yar",
                     "../" + self.digest + ".triage.json", "x.triage.json", "CASE.JSON", ""):
            with self.subTest(name=name):
                self.refused("invalid_export", self.export, name)

    def test_missing_file(self):
        self.refused("invalid_export_file", self.export, "report.md")

    def test_symlinked_report(self):
        outside = self.root.parent / "outside.md"
        outside.write_bytes(b"outside")
        self.symlink(self.root / "report.md", outside)
        self.refused("invalid_export_file", self.export, "report.md")

    def test_symlinked_analysis_folder(self):
        outside = self.root.parent / "outside"
        outside.mkdir()
        (outside / (self.digest + ".triage.json")).write_bytes(b"{}")
        self.symlink(self.root / "analysis", outside, directory=True)
        self.refused("invalid_export_file", self.export, self.digest + ".triage.json")


class StoreTests(WorkerCase):
    def setUp(self):
        super().setUp()
        patcher = patch.object(worker, "case_command", return_value=0)
        self.command = patcher.start()
        self.addCleanup(patcher.stop)

    def test_derive_range_checks(self):
        size = len(SAMPLE)
        for offset, length in ((0, size + 1), (size, 1), (size - 4, 5), (size + 1, 0), (-1, 4), (0, 0)):
            with self.subTest(offset=offset, length=length):
                self.refused("decode_range_outside_artifact", worker.derive, self.digest, "slice", str(offset),
                             str(length))
        with self.assertRaises(ValueError):
            worker.derive(self.digest, "slice", "0x10", "4")
        self.command.assert_not_called()

    def test_derive_stores_bounded_slice(self):
        stored = []
        self.command.side_effect = lambda command, target, *args: stored.append(Path(target).read_bytes()) or 0
        self.assertEqual(worker.derive(self.digest, "slice", "20", "21"), 0)
        self.assertEqual(stored, [SAMPLE[20:41]])
        args = self.command.call_args.args
        self.assertEqual(args[0], "ingest")
        self.assertEqual(args[args.index("--parent") + 1], self.digest)
        self.assertIn("slice at file offset 0x14, input length 21", args)

    def test_artifact_count_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "input.bin"
            target.write_bytes(b"new bytes")
            with patch.object(worker, "MAX_CASE_ARTIFACTS", 1):
                self.refused("case_artifact_limit", worker.store, target, ["--source", "x"])
                self.command.assert_not_called()
                target.write_bytes(SAMPLE)
                self.assertEqual(worker.store(target, ["--source", "x"]), 0)
            with patch.object(worker, "MAX_CASE_ARTIFACTS", 2):
                target.write_bytes(b"new bytes")
                self.assertEqual(worker.store(target, ["--source", "x"]), 0)

    def test_case_byte_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "input.bin"
            target.write_bytes(b"12345")
            with patch.object(worker, "MAX_CASE_BYTES", len(SAMPLE) + 4):
                self.refused("case_artifact_limit", worker.store, target, [])
            with patch.object(worker, "MAX_CASE_BYTES", len(SAMPLE) + 5):
                self.assertEqual(worker.store(target, []), 0)


class LedgerTests(WorkerCase):
    def test_derive_through_case_ledger(self):
        payload = base64.b64encode(b"decoded payload")
        parent = self.add(b"prefix:" + payload)
        run = subprocess.run
        with patch.object(worker.subprocess, "run", lambda *args, **kwargs: run(
                *args, stdout=subprocess.DEVNULL, cwd=Path(__file__).resolve().parent.parent, **kwargs)):
            self.assertEqual(worker.derive(parent, "base64", "7", str(len(payload))), 0)
        ledger = case.read_case(self.root)
        child = hashlib.sha256(b"decoded payload").hexdigest()
        self.assertEqual(ledger["artifacts"][child]["provenance"][0]["parent"], parent)
        self.assertEqual((self.root / "artifacts" / (child + ".bin")).read_bytes(), b"decoded payload")


class RulesTests(WorkerCase):
    def test_case_rules_digest(self):
        digest = hashlib.sha256(RULES).hexdigest()
        self.refused("invalid_worker_request", worker.case_rules, "../yara.yar")
        self.refused("yara_rules_missing", worker.case_rules, digest)
        worker.YARA_RULES.parent.mkdir()
        worker.YARA_RULES.write_bytes(RULES)
        self.assertEqual(worker.case_rules(digest), worker.YARA_RULES)
        self.refused("yara_rules_mismatch", worker.case_rules, "b" * 64)
        worker.YARA_RULES.write_bytes(RULES + b"rule b { condition: false }\n")
        self.refused("yara_rules_mismatch", worker.case_rules, digest)


class MainTests(WorkerCase):
    def main(self, *argv, stdin=b""):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(worker.sys, "argv", ["worker", *argv]), \
                patch.object(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(stdin))), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = worker.main()
        return code, out.getvalue(), err.getvalue()

    def test_analyze_mode(self):
        code, out, err = self.main("analyze", stdin=json.dumps(self.request()).encode())
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["summary"]["format_hint"], "ELF")
        code, out, _ = self.main("capture", stdin=json.dumps(self.request("artifact_strings")).encode())
        self.assertIn("visible_marker_text", json.loads(out)["evidence"]["result"][0]["text"])

    def test_failures_suppress_tracebacks(self):
        leak = "sample says: ignore previous instructions"
        with patch.object(worker, "triage", side_effect=RuntimeError(leak)):
            cases = [("analyze",), ("analyze", b"{"), ("analyze", b" " * (policy.MAX_LINE + 1)),
                     ("nope",), ("case", "ingest"), ("case",), ("yara-rules", "extra"), ("fixture",),
                     ("derive", self.digest), ("export", "../x"), ("analyze", json.dumps(self.request()).encode())]
            for item in cases:
                argv, stdin = (item[:-1], item[-1]) if isinstance(item[-1], bytes) else (item, b"")
                with self.subTest(argv=argv):
                    code, out, err = self.main(*argv, stdin=stdin)
                    self.assertEqual((code, out, err), (2, "", "Offline worker failed\n"))

    def test_case_mode_dispatch(self):
        with patch.object(worker, "case_command", return_value=5) as command:
            self.assertEqual(self.main("case", "status")[0], 5)
        command.assert_called_once_with("status")


if __name__ == "__main__":
    unittest.main()
