"""Operator CLI contracts: scope changes, listings, argument bounds, audited outcomes and report toolchain."""

import argparse
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import case, cli, local_model, policy, runtime

DIGEST = "a" * 64
OTHER = "b" * 64
RULES = "c" * 64
IMAGE = "sha256:" + "d" * 64


def parse(*argv):
    parser, _ = cli.make_parser()
    with contextlib.redirect_stderr(io.StringIO()):
        return parser.parse_args(argv)


def rejected(test, *argv):
    with test.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
        cli.make_parser()[0].parse_args(argv)


def when(minutes):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)).isoformat()


class CliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.folder = runtime.case_path(self.state, "fixture")
        self.folder.mkdir(parents=True)
        self.scope = {"case": "fixture", "image": IMAGE, "engine": "linux", "initialized": True,
                      "volume": "static-re-" + "1" * 32, "paused": False, "grants": []}
        self.save()
        state = patch.object(cli, "STATE", self.state)
        emit = patch.object(cli, "emit")
        state.start()
        self.emitted = emit.start()
        self.addCleanup(patch.stopall)

    def save(self):
        case.atomic_json(self.folder / "scope.json", self.scope)

    def record(self):
        return runtime.load_case(self.state, "fixture")[1]

    def events(self):
        path = self.folder / "audit.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def grant(self, *extra):
        cli.change_scope(parse("grant", "fixture", "artifact_strings", DIGEST, *extra))

    def act(self, *argv, reply=b"{}"):
        with patch.object(cli, "call_worker", return_value=reply) as worker, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            cli.operator_action(parse(*argv))
        return worker, output.getvalue()

    # Grants and listings

    def test_grant_prunes_expired_and_caps_active(self):
        self.scope["grants"] = [{"id": "1" * 32, "tool": "artifact_strings", "audience": "local",
                                 "arguments": {"artifact": DIGEST, "offset": 0, "limit": 20}, "expires_utc": when(-1)}]
        self.save()
        self.grant("--offset", "5", "--limit", "10", "--minutes", "3")
        grants = self.record()["grants"]
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["arguments"], {"artifact": DIGEST, "offset": 5, "limit": 10})
        self.assertEqual(self.events()[-1]["pruned"], ["1" * 32])
        self.scope["grants"] = [dict(grants[0], id=f"{index:032x}") for index in range(cli.MAX_GRANTS)]
        self.save()
        with self.assertRaisesRegex(runtime.RuntimeFailure, "Too many"):
            self.grant()
        self.assertEqual(len(self.record()["grants"]), cli.MAX_GRANTS)

    def test_grant_refuses_a_paused_case_and_revoke_needs_a_known_id(self):
        self.scope["paused"] = True
        self.save()
        with self.assertRaisesRegex(runtime.RuntimeFailure, "Resume"):
            self.grant()
        self.assertEqual(self.record()["grants"], [])
        with self.assertRaisesRegex(runtime.RuntimeFailure, "Unknown grant"):
            cli.change_scope(parse("revoke", "fixture", "f" * 32))
        self.assertEqual(self.events(), [])

    def test_grants_lists_active_and_audits_the_prune(self):
        live = {"id": "2" * 32, "tool": "ghidra_decompile", "audience": "mcp", "expires_utc": when(5),
                "arguments": {"artifact": DIGEST, "address": "0x401000"}}
        self.scope["grants"] = [live, dict(live, id="3" * 32, expires_utc=when(-5))]
        self.save()
        cli.list_grants(parse("grants", "fixture"))
        listed = self.emitted.call_args.args[0]["grants"]
        self.assertEqual(listed, [{"id": "2" * 32, "tool": "ghidra_decompile", "artifact": DIGEST,
                                   "selector": {"address": "0x401000"}, "audience": "mcp",
                                   "expires_utc": live["expires_utc"]}])
        self.assertEqual([grant["id"] for grant in self.record()["grants"]], ["2" * 32])
        self.assertEqual(self.events()[-1], {**self.events()[-1], "decision": "grants_pruned", "pruned": ["3" * 32]})
        cli.list_grants(parse("grants", "fixture"))
        self.assertEqual(len(self.events()), 1)

    def test_cases_reports_scope_without_writing(self):
        self.scope["yara_rules"] = {"sha256": RULES, "rules": 1, "bytes": 10}
        self.save()
        pending = runtime.case_path(self.state, "pending")
        pending.mkdir()
        case.atomic_json(pending / "scope.json", {**self.scope, "case": "pending", "initialized": False,
                                                  "paused": True, "yara_rules": None})
        (self.state / "cases" / "Not_A_Case").mkdir()
        before = (self.folder / "scope.json").read_bytes()
        cli.list_cases(parse("cases"))
        rows = self.emitted.call_args.args[0]["cases"]
        self.assertEqual(rows[0], {"case": "fixture", "paused": False, "initialized": True, "closed": False,
                                   "image": IMAGE, "yara_rules_sha256": RULES})
        self.assertEqual(rows[1], {"case": "pending", "error": "Unreadable or invalid case scope record"})
        self.assertEqual(len(rows), 2)
        self.assertEqual((self.folder / "scope.json").read_bytes(), before)
        self.assertEqual(self.events(), [])

    # Argument bounds

    def test_parser_choices_and_text_bounds(self):
        self.assertEqual(parse("grant", "fixture", "artifact_strings", DIGEST, "--minutes", "60").minutes, 60)
        for argv in (("grant", "fixture", "artifact_strings", DIGEST, "--minutes", "0"),
                     ("grant", "fixture", "artifact_strings", DIGEST, "--minutes", "61"),
                     ("grant", "fixture", "artifact_summary", DIGEST)):
            with self.subTest(argv=argv):
                rejected(self, *argv)
        finding = ("finding", "fixture", "--artifact", DIGEST, "--kind", "observed", "--confidence", "low")
        self.assertEqual(len(parse(*finding, "--claim", "x" * 2000, *["--evidence", "e" * 500] * 16).evidence), 16)
        for extra in (("--claim", "x" * 2001, "--evidence", "e"), ("--claim", "x", "--evidence", "e" * 501),
                      ("--claim", "x", *["--evidence", "e"] * 17)):
            with self.subTest(extra=len(extra)):
                rejected(self, *finding, *extra)
        valid = (*finding, "--claim", "x", "--evidence", "e")
        self.assertEqual(parse(*valid, "--supersedes", "F00012").supersedes, "F00012")
        for target in ("F001", "f0001", "F0001 ", "0001", "F" + "1" * 16, "--x"):
            with self.subTest(target=target):
                rejected(self, *valid, "--supersedes", target)

    def test_source_and_relation_labels_are_sanitized(self):
        base = ("ingest", "fixture", "drop.bin", "--parent", DIGEST)
        self.assertEqual(parse(*base, "--source", "Operator handoff (42)", "--relation", "RT_RCDATA 101, zlib")
                         .relation, "RT_RCDATA 101, zlib")
        for flag in ("--source", "--relation"):
            for label in ("https://host/x", "user:pass", " leading", "x" * 161, "line\nbreak"):
                other = "--relation" if flag == "--source" else "--source"
                with self.subTest(flag=flag, label=label):
                    rejected(self, *base, other, "ok", flag, label)
        sample = self.state / "drop.bin"
        sample.write_bytes(b"MZ")
        args = parse("ingest", "fixture", str(sample), "--source", "ok")
        args.relation = "http://example"
        with patch.object(cli, "call_worker") as worker, self.assertRaises(runtime.RuntimeFailure):
            cli.operator_action(args)
        worker.assert_not_called()
        self.assertEqual([event["decision"] for event in self.events()], ["operator_requested", "operator_failed"])

    def test_derive_bounds_are_checked_before_the_worker(self):
        for argv in ((OTHER[:-1], "base64", "0", "16"), (DIGEST, "base64", "-1", "16"),
                     (DIGEST, "zlib", str(policy.MAX_ARTIFACT), "16"), (DIGEST, "slice", "0", "0"),
                     (DIGEST, "slice", "0", str(cli.decoding.INPUT_CAP + 1))):
            with self.subTest(argv=argv), patch.object(cli, "call_worker") as worker, \
                    self.assertRaises(runtime.RuntimeFailure):
                cli.operator_action(parse("derive", "fixture", *argv))
            worker.assert_not_called()
        worker, _ = self.act("derive", "fixture", DIGEST, "gzip", "0x10", "0x20",
                             reply=json.dumps({"sha256": OTHER}).encode())
        self.assertEqual(worker.call_args.args[1], ["derive", DIGEST, "gzip", "16", "32"])
        self.assertEqual(self.events()[-1]["sha256"], OTHER)

    # Outputs

    def test_export_raw_artifacts_need_bin_and_outputs_never_overwrite(self):
        with patch.object(cli, "call_worker") as worker, self.assertRaisesRegex(runtime.RuntimeFailure, ".bin"):
            cli.operator_action(parse("export", "fixture", DIGEST, str(self.state / "sample.exe")))
        worker.assert_not_called()
        existing = self.state / "report.md"
        existing.write_text("keep")
        with patch.object(cli, "call_worker") as worker, self.assertRaisesRegex(runtime.RuntimeFailure, "exists"):
            cli.operator_action(parse("export", "fixture", "report.md", str(existing)))
        worker.assert_not_called()
        self.assertEqual(existing.read_text(), "keep")
        target = self.state / "sample.BIN"
        with patch.object(cli, "call_worker", side_effect=lambda *_a, output, **_k: output.write(b"MZ")), \
                contextlib.redirect_stdout(io.StringIO()):
            cli.operator_action(parse("export", "fixture", DIGEST, str(target)))
        self.assertEqual(target.read_bytes(), b"MZ")
        self.assertEqual([path.name for path in self.state.iterdir() if path.name.startswith(".static-re-")], [])
        self.assertEqual(self.events()[-1]["item"], DIGEST)

    def test_output_file_cleans_up_after_a_failed_writer(self):
        def failing(stream):
            stream.write(b"partial")
            raise runtime.RuntimeFailure("worker failed")

        with self.assertRaises(runtime.RuntimeFailure):
            cli.output_file(self.state / "out.json", failing)
        self.assertEqual(sorted(path.name for path in self.state.iterdir()), ["cases"])

    def test_hookup_formats(self):
        for form in ("codex", "json"):
            with self.subTest(form=form), contextlib.redirect_stdout(io.StringIO()) as output, \
                    patch.object(cli, "emit", side_effect=lambda value: print(json.dumps(value))):
                cli.hookup(parse("hookup", "fixture", "--format", form))
            text = output.getvalue()
            if form == "codex":
                self.assertTrue(text.startswith("[mcp_servers.static_re]\n"))
                self.assertIn('args = ["-m", "re_harness.cli", "serve", "fixture"]', text)
                self.assertIn("STATIC_RE_STATE_DIR = " + json.dumps(str(self.state)), text)
                self.assertIn("tool_timeout_sec = 330", text)
            else:
                value = json.loads(text)
                self.assertEqual(value["args"], ["-m", "re_harness.cli", "serve", "fixture"])
                self.assertEqual((value["env"], value["tool_timeout_seconds"]),
                                 ({"STATIC_RE_STATE_DIR": str(self.state)}, 330))
        self.assertEqual(parse("hookup", "fixture").format, "codex")
        rejected(self, "hookup", "fixture", "--format", "yaml")

    # Audit and report toolchain

    def test_audit_records_validated_inspect_request_and_output_digest(self):
        target = self.state / "capture.json"
        with patch.object(cli, "call_worker", side_effect=lambda *_a, output, **_k: output.write(b"{}")) as worker, \
                contextlib.redirect_stdout(io.StringIO()):
            cli.operator_action(parse("inspect", "fixture", "ghidra_decompile", DIGEST, "--address", "0x00401000",
                                      "--full", "--output", str(target)))
        self.assertEqual(worker.call_args.args[1], ["capture"])
        requested, completed = self.events()
        arguments = {"artifact": DIGEST, "address": "0x401000"}
        for event in (requested, completed):
            self.assertEqual((event["operation"], event["tool"], event["artifact"], event["arguments"]),
                             ("inspect", "ghidra_decompile", DIGEST, arguments))
        self.assertEqual(completed["decision"], "operator_completed")
        self.assertEqual(completed["output_sha256"], case.hashes(target)[1]["sha256"])

    def test_ingest_audits_the_admitted_digest(self):
        sample = self.state / "drop.bin"
        sample.write_bytes(b"MZ")
        worker, output = self.act("ingest", "fixture", str(sample), "--source", "Operator handoff",
                                  reply=json.dumps({"sha256": OTHER, "size": 2}).encode())
        self.assertIn("--source=Operator handoff", worker.call_args.args[1])
        self.assertEqual(self.events()[-1]["sha256"], OTHER)
        self.assertIn(OTHER, output)

    def test_failing_worker_audits_a_fixed_reason(self):
        with patch.object(cli, "call_worker", side_effect=runtime.RuntimeFailure("C:\\secret\\path detail")), \
                self.assertRaises(runtime.RuntimeFailure):
            cli.operator_action(parse("status", "fixture"))
        requested, failed = self.events()
        self.assertEqual(requested["decision"], "operator_requested")
        self.assertEqual(failed, {**failed, "decision": "operator_failed", "reason": "operation_failed",
                                  "operation": "status"})
        self.assertNotIn("secret", json.dumps(failed))
        with patch.object(cli, "call_worker", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            cli.operator_action(parse("verify", "fixture"))
        self.assertEqual(self.events()[-1]["reason"], "interrupted")

    def test_finding_passes_supersedes_to_the_ledger(self):
        worker, _ = self.act("finding", "fixture", "--artifact", DIGEST, "--kind", "inferred", "--confidence", "low",
                             "--claim", "Revised", "--evidence", "e", "--supersedes", "F0001")
        self.assertIn("--supersedes=F0001", worker.call_args.args[1])
        worker, _ = self.act("finding", "fixture", "--artifact", DIGEST, "--kind", "inferred", "--confidence", "low",
                             "--claim", "New", "--evidence", "e")
        self.assertFalse(any(value.startswith("--supersedes") for value in worker.call_args.args[1]))

    def test_report_passes_the_case_toolchain(self):
        worker, _ = self.act("report", "fixture")
        self.assertEqual(worker.call_args.args[1], ["case", "report", "--image", IMAGE])
        self.assertTrue(worker.call_args.kwargs["writable"])
        self.scope["yara_rules"] = {"sha256": RULES, "rules": 1, "bytes": 10}
        self.save()
        worker, _ = self.act("report", "fixture")
        self.assertEqual(worker.call_args.args[1],
                         ["case", "report", "--image", IMAGE, "--yara-rules-sha256", RULES])

    # Closure

    def close(self, *replies):
        report = {"report": "/case/report.md", "evidence": "/case/evidence.json", "case_sha256": OTHER,
                  "report_sha256": RULES}
        replies = replies or (json.dumps({"ok": True, "checked": 1, "problems": []}).encode(),
                              json.dumps(report).encode())
        with patch.object(cli, "call_worker", side_effect=list(replies)) as worker:
            cli.close_case(parse("close", "fixture"))
        return worker

    def closed_case(self):
        self.scope["grants"] = [{"id": "4" * 32, "tool": "artifact_strings", "audience": "local",
                                 "arguments": {"artifact": DIGEST, "offset": 0, "limit": 20}, "expires_utc": when(5)},
                                {"id": "5" * 32, "tool": "artifact_strings", "audience": "mcp",
                                 "arguments": {"artifact": DIGEST, "offset": 0, "limit": 20}, "expires_utc": when(-5)}]
        self.scope["yara_rules"] = {"sha256": RULES, "rules": 1, "bytes": 10}
        self.save()
        return self.close()

    def test_close_verifies_reports_drops_grants_and_audits(self):
        worker = self.closed_case()
        (verify, _), (report, options) = [(call.args, call.kwargs) for call in worker.call_args_list]
        self.assertEqual(verify[1], ["case", "verify"])
        self.assertEqual(report[1], ["case", "report", "--image", IMAGE, "--yara-rules-sha256", RULES])
        self.assertTrue(options["writable"])
        record = runtime.load_case(self.state, "fixture", allow_closed=True)[1]
        self.assertEqual((record["closed"], record["grants"], record["volume"]), (True, [], self.scope["volume"]))
        requested, closed = self.events()
        self.assertEqual((requested["decision"], requested["operation"]), ("operator_requested", "close"))
        self.assertEqual(closed, {**closed, "decision": "case_closed", "operation": "close", "report_sha256": RULES,
                                  "case_sha256": OTHER, "retired_grants": ["4" * 32, "5" * 32],
                                  "closed_utc": record["closed_utc"]})
        self.assertEqual(self.emitted.call_args.args[0]["decision"], "case_closed")
        with patch.object(cli, "call_worker") as again, self.assertRaisesRegex(runtime.RuntimeFailure, "Case is closed"):
            cli.close_case(parse("close", "fixture"))
        again.assert_not_called()
        self.assertEqual(len(self.events()), 2)

    def test_close_omits_an_unusable_report_digest(self):
        self.close(json.dumps({"ok": True}).encode(), json.dumps({"report_sha256": "x"}).encode())
        self.assertNotIn("report_sha256", self.events()[-1])
        self.assertTrue(runtime.load_case(self.state, "fixture", allow_closed=True)[1]["closed"])

    def test_close_refuses_when_verify_or_report_fails(self):
        self.scope["grants"] = [{"id": "4" * 32, "tool": "artifact_strings", "audience": "local",
                                 "arguments": {"artifact": DIGEST, "offset": 0, "limit": 20}, "expires_utc": when(5)}]
        self.save()
        before = (self.folder / "scope.json").read_bytes()
        failures = ((json.dumps({"ok": False, "problems": [{"error": "Hash or size mismatch"}]}).encode(),),
                    (runtime.RuntimeFailure("The offline Apprentice did not complete the operation"),),
                    (b"not json",))
        for replies in failures:
            with self.subTest(replies=replies), patch.object(cli, "call_worker", side_effect=list(replies)) as worker, \
                    self.assertRaisesRegex(runtime.RuntimeFailure, "Ledger verification failed"):
                cli.close_case(parse("close", "fixture"))
            self.assertEqual(worker.call_count, 1)
            self.assertEqual(self.events()[-1], {**self.events()[-1], "decision": "operator_failed",
                                                 "reason": "verify_failed", "operation": "close"})
        with patch.object(cli, "call_worker", side_effect=[json.dumps({"ok": True}).encode(),
                                                           runtime.RuntimeFailure("report")]), \
                self.assertRaises(runtime.RuntimeFailure):
            cli.close_case(parse("close", "fixture"))
        self.assertEqual(self.events()[-1]["reason"], "report_failed")
        self.assertEqual((self.folder / "scope.json").read_bytes(), before)
        self.assertNotIn("closed", self.record())

    def test_closed_case_refuses_changes_and_analysis(self):
        self.closed_case()
        sample = self.state / "drop.bin"
        sample.write_bytes(b"MZ")
        rules = self.state / "rules.yar"
        rules.write_text("rule a { condition: true }")
        before = (self.folder / "scope.json").read_bytes()
        count = len(self.events())
        refused = [(cli.operator_action, argv) for argv in (
            ("ingest", "fixture", str(sample), "--source", "ok"), ("derive", "fixture", DIGEST, "slice", "0", "16"),
            ("triage", "fixture", DIGEST), ("report", "fixture"),
            ("finding", "fixture", "--artifact", DIGEST, "--kind", "observed", "--confidence", "low", "--claim", "c",
             "--evidence", "e"),
            ("inspect", "fixture", "artifact_summary", DIGEST, "--output", str(self.state / "out.json")))]
        refused += [(cli.change_scope, argv) for argv in (
            ("grant", "fixture", "artifact_strings", DIGEST), ("resume", "fixture"), ("pause", "fixture"),
            ("revoke", "fixture", "4" * 32))]
        refused += [(cli.import_yara_rules, ("yara-rules", "fixture", str(rules))), (cli.hookup, ("hookup", "fixture")),
                    (cli.init_case, ("init", "fixture", "--title", "Again")), (cli.close_case, ("close", "fixture"))]
        for handler, argv in refused:
            with self.subTest(argv=argv), patch.object(cli, "call_worker") as worker, \
                    patch.object(runtime, "docker") as docker, \
                    self.assertRaisesRegex(runtime.RuntimeFailure, "Case is closed"):
                handler(parse(*argv))
            worker.assert_not_called()
            docker.assert_not_called()
        with patch.object(local_model, "ollama") as ollama, patch.object(runtime, "worker") as worker, \
                self.assertRaisesRegex(runtime.RuntimeFailure, "Case is closed"):
            local_model.chat(self.state, "fixture", 11434, "model", "native", "Summarize")
        ollama.assert_not_called()
        worker.assert_not_called()
        self.assertEqual((self.folder / "scope.json").read_bytes(), before)
        self.assertFalse((self.state / "out.json").exists())
        events = self.events()[count:]
        self.assertEqual([(event["decision"], event["reason"], event["audience"]) for event in events],
                         [("intercepted", "case_closed", "local")])

    def test_closed_case_keeps_read_operations(self):
        self.closed_case()
        for argv in (("status", "fixture"), ("verify", "fixture")):
            with self.subTest(argv=argv):
                worker, _ = self.act(*argv)
                self.assertEqual(worker.call_args.args[1], ["case", argv[0]])
                self.assertFalse(worker.call_args.kwargs["writable"])
        target = self.state / "report.md"
        with patch.object(cli, "call_worker", side_effect=lambda *_a, output, **_k: output.write(b"# Report")), \
                contextlib.redirect_stdout(io.StringIO()):
            cli.operator_action(parse("export", "fixture", "report.md", str(target)))
        self.assertEqual(target.read_bytes(), b"# Report")
        self.assertEqual(self.events()[-1]["decision"], "operator_completed")
        cli.list_grants(parse("grants", "fixture"))
        self.assertEqual(self.emitted.call_args.args[0]["grants"], [])
        cli.list_cases(parse("cases"))
        self.assertTrue(self.emitted.call_args.args[0]["cases"][0]["closed"])


if __name__ == "__main__":
    unittest.main()
