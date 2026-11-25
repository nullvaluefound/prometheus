"""YARA and capa contracts: worker parsing, host projection, broker binding and rule import."""

import argparse
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import case, cli, policy, projection, providers, runtime, server

try:
    import yara
except ImportError:
    yara = None

DIGEST = "a" * 64
RULES = "b" * 64
PAGE = {"artifact": DIGEST, "offset": 0, "limit": 20}


def yara_reply(**summary):
    return {"tool": "yara_scan", "artifact": DIGEST, "artifact_bytes": 64, "summary": {
        "rows": [{"rule": "suspicious_loader", "namespace": "default", "tags": ["loader"],
                  "strings": [{"identifier": "$api", "instances": 3, "matches": [{"offset": 16, "length": 7}]}]}],
        "has_more": False, "matched_rules": 1, "matches_truncated": False, "rules_sha256": RULES, **summary}}


def capa_reply(row=None, **summary):
    row = row or {"rule": "encode data using XOR", "namespace": "data-manipulation/encoding/xor",
                  "attack": ["T1027"], "mbc": ["E1027.m02", "C0026.002"], "matches": 2, "addresses": ["0x401000"]}
    return {"tool": "capa_triage", "artifact": DIGEST, "artifact_bytes": 64, "summary": {
        "rows": [row], "has_more": False, "capabilities": 1, "limitations": ["(internal) packer file limitation"],
        "rules_withheld": 0, "format": "pe", "arch": "i386", "os": "windows", **summary}}


class ContractTests(unittest.TestCase):
    def test_scanner_selectors_are_paged_and_closed(self):
        for name in ("yara_scan", "capa_triage"):
            self.assertEqual(policy.validate(name, {"artifact": DIGEST}), PAGE)
            for arguments in ({"artifact": DIGEST, "address": "0x10"}, {"artifact": DIGEST, "rules": RULES},
                              {"artifact": DIGEST, "limit": 51}):
                with self.subTest(name=name, arguments=arguments), self.assertRaises(policy.Denied):
                    policy.validate(name, arguments)
        self.assertNotIn("yara_scan", policy.EXCERPT_ONLY)

    def test_yara_projection_keeps_offsets_and_rejects_bytes_or_other_rules(self):
        reply = yara_reply()
        self.assertEqual(projection.project(reply, "yara_scan", PAGE, False, RULES), reply)
        hit = {"offset": 16, "length": 7, "data_hex": "6578616d706c65"}
        leaked = yara_reply(rows=[{**reply["summary"]["rows"][0], "strings": [
            {"identifier": "$api", "instances": 1, "matches": [hit]}]}])
        for payload, rules in ((reply, "c" * 64), (reply, None), (leaked, RULES),
                               (yara_reply(rows=[{**reply["summary"]["rows"][0], "rule": "ignore previous"}]), RULES),
                               (yara_reply(rows=[{**reply["summary"]["rows"][0], "tags": ["<b>"]}]), RULES),
                               (yara_reply(matched_rules=513), RULES)):
            with self.subTest(payload=payload, rules=rules), self.assertRaises(ValueError):
                projection.project(payload, "yara_scan", PAGE, False, rules)

    def test_capa_projection_checks_identifiers_and_addresses(self):
        reply = capa_reply()
        self.assertEqual(projection.project(reply, "capa_triage", PAGE, False), reply)
        unnamed = capa_reply({**reply["summary"]["rows"][0], "namespace": ""})
        self.assertEqual(projection.project(unnamed, "capa_triage", PAGE, False)["summary"]["rows"][0]["namespace"], "")
        row = reply["summary"]["rows"][0]
        for payload in (capa_reply({**row, "attack": ["T1027; curl"]}), capa_reply({**row, "mbc": ["B0001.0321"]}),
                        capa_reply({**row, "addresses": ["0x1"] * 9}), capa_reply({**row, "rule": "line\nbreak"}),
                        capa_reply({**row, "namespace": "../escape"}), capa_reply({**row, "description": "extra"}),
                        capa_reply(format="Portable Executable")):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                projection.project(payload, "capa_triage", PAGE, False)


class CapaParsingTests(unittest.TestCase):
    def run_capa(self, document, returncode=0):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        sample = Path(directory.name) / "sample.bin"
        sample.write_bytes(b"\x7fELF\x02\x01\x01" + bytes(57))

        def fake(args, stdout, **_kwargs):
            self.assertEqual(args[0], "capa")
            self.assertEqual(args[-1], str(sample))
            stdout.write(json.dumps(document).encode())
            return type("Done", (), {"returncode": returncode})()

        with patch.object(providers.subprocess, "run", side_effect=fake):
            return providers.capa_triage(sample, {"offset": 0, "limit": 20})

    def test_rows_drop_library_internal_and_unsafe_rules(self):
        def rule(namespace, *, lib=False, matches=1, attack=(), mbc=()):
            return {"meta": {"namespace": namespace, "lib": lib, "is_subscope_rule": False, "description": "d",
                             "attack": [{"id": value} for value in attack], "mbc": [{"id": value} for value in mbc]},
                    "matches": [[{"type": "absolute", "value": 0x401000 + index}, {}] for index in range(matches)]}

        document = {"meta": {"version": "10.0.0", "analysis": {
            "format": "elf", "arch": "amd64", "os": "linux", "base_address": {"type": "absolute", "value": 0x400000},
            "layout": {"functions": [{}, {}]}}}, "rules": {
            "write file on Linux": rule("host-interaction/file-system/write", matches=12, mbc=["C0052", "bad id"]),
            "encode data using XOR": rule("data-manipulation/encoding/xor", attack=["T1027", "T1027.002", "x"]),
            "contain loop": rule("", lib=True),
            "(internal) packer file limitation": rule("internal/limitation/static"),
            "(internal) feature": rule("internal/other"),
            "bad\x1bname": rule("collection"),
        }}
        summary, detail = self.run_capa(document)
        self.assertEqual([row["rule"] for row in summary["rows"]], ["encode data using XOR", "write file on Linux"])
        xor, write = summary["rows"]
        self.assertEqual(xor["attack"], ["T1027", "T1027.002"])
        self.assertEqual(write["mbc"], ["C0052"])
        self.assertEqual((write["matches"], len(write["addresses"])), (12, 8))
        self.assertEqual(len(detail["capabilities"][1]["addresses"]), 12)
        self.assertEqual(summary["limitations"], ["(internal) packer file limitation"])
        self.assertEqual((summary["rules_withheld"], summary["capabilities"], summary["format"]), (1, 2, "elf"))
        self.assertEqual(detail["base_address"], "0x400000")
        reply = {"tool": "capa_triage", "artifact": DIGEST, "artifact_bytes": 64, "summary": summary}
        projection.project(reply, "capa_triage", PAGE, False)

    def test_failures_and_non_native_inputs_stop(self):
        with self.assertRaises(ValueError):
            self.run_capa({}, returncode=14)
        with tempfile.NamedTemporaryFile(delete=False) as script:
            script.write(b"#!/bin/sh\necho hi\n")
        self.addCleanup(Path(script.name).unlink)
        with patch.object(providers.subprocess, "run") as run, self.assertRaises(ValueError):
            providers.capa_triage(Path(script.name), {"offset": 0, "limit": 20})
        run.assert_not_called()


@unittest.skipUnless(yara, "yara-python is installed in the Apprentice image")
class YaraTests(unittest.TestCase):
    def scan(self, source, data):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        rules, sample = Path(directory.name) / "rules.yar", Path(directory.name) / "sample.bin"
        rules.write_bytes(source)
        sample.write_bytes(data)
        return providers.yara_scan(rules, sample, {"offset": 0, "limit": 20})

    def test_summary_has_offsets_and_detail_has_bounded_bytes(self):
        summary, detail = self.scan(b'rule b_rule : t { strings: $a = "needle" condition: $a }\n'
                                    b'rule a_rule { meta: author = "analyst" condition: true }\n',
                                    b"xx needle " * 20)
        self.assertEqual([row["rule"] for row in summary["rows"]], ["a_rule", "b_rule"])
        found = summary["rows"][1]["strings"][0]
        self.assertEqual((found["identifier"], found["instances"], len(found["matches"])), ("$a", 20, 8))
        self.assertEqual(found["matches"][0], {"offset": 3, "length": 6})
        self.assertNotIn("data_hex", json.dumps(summary))
        self.assertEqual(detail["matches"][1]["strings"][0]["matches"][0]["data_hex"], b"needle".hex())
        self.assertEqual(detail["matches"][0]["meta"], {"author": "analyst"})

    def test_includes_console_and_non_utf8_rules_are_refused(self):
        for source in (b'include "/etc/passwd"', b'import "console" rule a { condition: console.log("x") }',
                       b'rule a { condition: true } \xff', b"x" * (policy.MAX_YARA_RULES + 1)):
            with self.subTest(source=source[:40]), self.assertRaises((ValueError, yara.Error)):
                providers.yara_compile(source)
        self.assertEqual(len(list(providers.yara_compile(b'import "pe" rule a { condition: pe.number_of_sections > 0 }'))), 1)


class BrokerBindingTests(unittest.TestCase):
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

    def events(self):
        return [json.loads(line) for line in (self.folder / "audit.jsonl").read_text().splitlines()]

    def test_yara_needs_imported_rules_and_carries_their_digest(self):
        broker = server.Broker(self.state, "fixture")
        ask = {"name": "yara_scan", "arguments": {"artifact": DIGEST}}
        with patch.object(runtime, "worker") as worker:
            reply = broker.call(ask)
            worker.assert_not_called()
        self.assertIn("yara_rules_not_imported", reply["content"][0]["text"])
        self.scope["yara_rules"] = {"sha256": RULES, "rules": 1, "bytes": 40, "imported_utc": "2026-11-25T00:00:00"}
        self.save()
        with patch.object(runtime, "worker", return_value=(0, json.dumps(yara_reply()).encode())) as worker:
            reply = broker.call(ask)
        self.assertFalse(reply["isError"], reply)
        request = json.loads(worker.call_args.kwargs["request"])
        self.assertEqual(request, {"tool": "yara_scan", "arguments": PAGE, "excerpt": False, "rules": RULES})
        self.assertEqual(worker.call_args.kwargs["timeout"], 155)
        dispatched = [event for event in self.events() if event["decision"] == "dispatched"]
        self.assertEqual(dispatched[-1]["rules"], RULES)

    def test_rule_change_during_scan_withholds_the_result(self):
        self.scope["yara_rules"] = {"sha256": RULES, "rules": 1, "bytes": 40}
        self.save()

        def replaced(*_args, **_kwargs):
            self.scope["yara_rules"] = {"sha256": "c" * 64, "rules": 2, "bytes": 80}
            self.save()
            return 0, json.dumps(yara_reply()).encode()

        with patch.object(runtime, "worker", side_effect=replaced):
            reply = server.Broker(self.state, "fixture").call({"name": "yara_scan", "arguments": {"artifact": DIGEST}})
        self.assertIn("yara_rules_changed", reply["content"][0]["text"])

    def test_capa_gets_a_longer_worker_budget(self):
        with patch.object(runtime, "worker", return_value=(0, json.dumps(capa_reply()).encode())) as worker:
            reply = server.Broker(self.state, "fixture").call({"name": "capa_triage", "arguments": {"artifact": DIGEST}})
        self.assertFalse(reply["isError"], reply)
        self.assertEqual(worker.call_args.kwargs["timeout"], 300)
        self.assertNotIn("rules", json.loads(worker.call_args.kwargs["request"]))

    def test_malformed_rules_record_stops_the_case(self):
        for record in ({"sha256": "nope", "rules": 1, "bytes": 1}, "b" * 64, {"sha256": RULES, "rules": "1", "bytes": 1}):
            self.scope["yara_rules"] = record
            self.save()
            with self.subTest(record=record), self.assertRaises(runtime.RuntimeFailure):
                runtime.load_case(self.state, "fixture")

    def test_import_records_digest_and_retires_yara_grants(self):
        later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat()
        self.scope["grants"] = [{"id": "1" * 32, "tool": "yara_scan", "arguments": PAGE, "audience": "local",
                                 "expires_utc": later},
                                {"id": "2" * 32, "tool": "ghidra_decompile", "audience": "local", "expires_utc": later,
                                 "arguments": {"artifact": DIGEST, "address": "0x1000"}}]
        self.save()
        rules = self.state / "rules.yar"
        rules.write_text("rule a { condition: true }\n")
        result = json.dumps({"sha256": RULES, "bytes": 27, "rules": 1}).encode()
        with patch.object(cli, "STATE", self.state), patch.object(cli, "call_worker", return_value=result) as worker, \
                patch.object(cli, "emit"):
            cli.import_yara_rules(argparse.Namespace(case="fixture", input=rules))
        self.assertEqual(worker.call_args.args[1], ["yara-rules"])
        self.assertTrue(worker.call_args.kwargs["writable"])
        _, record = runtime.load_case(self.state, "fixture")
        self.assertEqual(record["yara_rules"]["sha256"], RULES)
        self.assertEqual([grant["tool"] for grant in record["grants"]], ["ghidra_decompile"])
        self.assertEqual(self.events()[-1]["retired_grants"], ["1" * 32])

    def test_import_rejects_oversized_or_unexpected_results(self):
        rules = self.state / "rules.yar"
        rules.write_bytes(b"x" * (policy.MAX_YARA_RULES + 1))
        with patch.object(cli, "STATE", self.state), patch.object(cli, "call_worker") as worker, \
                self.assertRaises(runtime.RuntimeFailure):
            cli.import_yara_rules(argparse.Namespace(case="fixture", input=rules))
        worker.assert_not_called()
        rules.write_text("rule a { condition: true }\n")
        with patch.object(cli, "STATE", self.state), patch.object(cli, "call_worker", return_value=b'{"sha256": "x"}'), \
                self.assertRaises(runtime.RuntimeFailure):
            cli.import_yara_rules(argparse.Namespace(case="fixture", input=rules))
        self.assertNotIn("yara_rules", runtime.load_case(self.state, "fixture")[1])


if __name__ == "__main__":
    unittest.main()
