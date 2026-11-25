"""Evidence ledger: ingest lineage, store integrity, triage hints, findings, defanging and report layout."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import case, projection

IMAGE = "sha256:" + "c" * 64
RULES = "d" * 64


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "case"
        self.assertEqual(self.run_case("init", "--title", "Loader hxxp case")[0], 0)

    def tearDown(self):
        self.tmp.cleanup()

    def run_case(self, command, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = case.main([command, str(self.root), *args])
            except SystemExit as exit:
                code = exit.code
        return code, json.loads(out.getvalue()) if out.getvalue() else None, err.getvalue()

    def sample(self, name, data):
        path = self.base / name
        path.write_bytes(data)
        return str(path)

    def ingest(self, data, *args, name="sample.bin"):
        return self.run_case("ingest", self.sample(name, data), "--source", "operator upload", *args)

    def ledger(self):
        return json.loads((self.root / "case.json").read_text(encoding="utf-8"))

    def test_ingest_requires_parent_and_relation_together(self):
        parent = self.ingest(b"parent bytes")[1]["sha256"]
        code, _, err = self.ingest(b"child bytes", "--parent", parent, name="child.bin")
        self.assertEqual(code, 2)
        self.assertIn("together", err)
        code, _, _ = self.ingest(b"child bytes", "--relation", "unpacked", name="child.bin")
        self.assertEqual(code, 2)
        code, _, err = self.ingest(b"child bytes", "--parent", "e" * 64, "--relation", "unpacked", name="child.bin")
        self.assertIn("Unknown artifact", err)
        code, child, _ = self.ingest(b"child bytes", "--parent", parent, "--relation", "unpacked‮",
                                     "--completeness", "partial", name="child.bin")
        self.assertEqual(code, 0)
        provenance = self.ledger()["artifacts"][child["sha256"]]["provenance"][0]
        self.assertEqual((provenance["parent"], provenance["relation"], provenance["completeness"]),
                         (parent, "unpacked", "partial"))

    def test_same_bytes_as_parent_is_refused(self):
        parent = self.ingest(b"same bytes")[1]["sha256"]
        code, _, err = self.ingest(b"same bytes", "--parent", parent, "--relation", "copy", name="copy.bin")
        self.assertEqual(code, 2)
        self.assertIn("same bytes", err)
        self.assertEqual(len(self.ledger()["artifacts"][parent]["provenance"]), 1)

    def test_corrupt_store_is_detected(self):
        digest = self.ingest(b"original bytes")[1]["sha256"]
        self.assertEqual(self.run_case("verify")[:2], (0, dict(ok=True, checked=1, problems=[])))
        (self.root / "artifacts" / (digest + ".bin")).write_bytes(b"tampered bytes")
        code, _, err = self.ingest(b"original bytes", name="again.bin")
        self.assertEqual(code, 2)
        self.assertIn("corrupt", err)
        code, result, _ = self.run_case("verify")
        self.assertEqual(code, 1)
        self.assertEqual(result["problems"], [dict(artifact=digest, error="Hash or size mismatch")])
        code, _, err = self.run_case("report")
        self.assertEqual(code, 2)
        self.assertIn("Integrity verification failed", err)
        self.assertFalse((self.root / "report.md").exists())
        self.assertFalse((self.root / "evidence.json").exists())

    def test_finding_ids_and_limits(self):
        digest = self.ingest(b"finding bytes")[1]["sha256"]
        base = ["--artifact", digest, "--kind", "observed", "--confidence", "low"]
        first = self.run_case("finding", *base, "--claim", "One", "--evidence", "a")[1]
        second = self.run_case("finding", *base, "--artifact", digest, "--claim", "Two", "--evidence", "b")[1]
        self.assertEqual((first["id"], second["id"]), ("F0001", "F0002"))
        self.assertEqual(second["artifacts"], [digest])
        for extra in (["--claim", "x" * 2001, "--evidence", "a"], ["--claim", "c", "--evidence", "x" * 501],
                      ["--claim", "c", *["--evidence", "e"] * 17]):
            code, _, err = self.run_case("finding", *base, *extra)
            self.assertEqual(code, 2)
            self.assertIn("exceeds", err)
        self.assertEqual(self.run_case("finding", *base, "--claim", "x" * 2000, *["--evidence", "y" * 500] * 16)[1]["id"],
                         "F0003")
        code, _, err = self.run_case("finding", "--artifact", "f" * 64, "--kind", "observed", "--confidence", "low",
                                     "--claim", "c", "--evidence", "e")
        self.assertIn("Unknown artifact", err)
        self.assertEqual(len(self.ledger()["findings"]), 3)

    def test_report_layout_and_toolchain(self):
        parent = self.ingest(b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x02\x00\x3e\x00" + b"evil-config-string")[1]["sha256"]
        child = self.ingest(b"child payload", "--parent", parent, "--relation", "carved", name="child.bin")[1]["sha256"]
        with patch.object(case, "STRING_LIMIT", 0):
            self.assertEqual(self.run_case("triage", parent)[0], 0)
        self.run_case("finding", "--artifact", parent, "--kind", "observed", "--confidence", "high",
                      "--claim", "Beacons to http://c2.example.com/gate", "--evidence", "offset 0x10 holds 10.1.2.3")
        self.run_case("finding", "--artifact", parent, "--kind", "unknown", "--confidence", "low",
                      "--claim", "Second stage purpose", "--evidence", "not acquired")
        code, _, err = self.run_case("report", "--image", "sha256:XYZ")
        self.assertEqual(code, 2)
        code, _, err = self.run_case("report", "--yara-rules-sha256", "D" * 64)
        self.assertEqual(code, 2)
        code, result, _ = self.run_case("report", "--image", IMAGE, "--yara-rules-sha256", RULES)
        self.assertEqual(code, 0)
        raw = (self.root / "report.md").read_bytes()
        self.assertNotIn(b"\r", raw)
        text = raw.decode("utf-8")
        headings = [line for line in text.splitlines() if line.startswith("## ")]
        self.assertEqual(headings, ["## Assessment", "## Artifacts", "## Coverage", "## Findings", "## Unknowns",
                                    "## Limitations", "## Indicators", "## Ledger verification"])
        self.assertIn(f"- Worker image `{IMAGE}`", text)
        self.assertIn(f"- YARA rules SHA-256 `{RULES}`", text)
        record = self.ledger()["artifacts"][parent]
        for value in (record["hashes"]["md5"], record["hashes"]["sha1"], "- Format hint ELF",
                      "- Format hint not triaged", f"  - Parent `{parent}`, carved",
                      "- 1 of 2 artifacts are cited by findings", f"  - With findings `{parent}`",
                      f"  - Without findings `{child}`", f"- Partial or unknown completeness `{child}`",
                      "### Observed", "hxxp://c2[.]example[.]com/gate", "10[.]1[.]2[.]3",
                      f"`{parent}`: String scan truncated at 0 strings", "- Passed: 2 artifacts checked, 0 problems",
                      "case.json SHA-256 `" + hashlib.sha256((self.root / "case.json").read_bytes()).hexdigest()):
            self.assertIn(value, text)
        self.assertNotIn("### Unknown", text)
        unknowns = text.split("## Unknowns")[1].split("## Limitations")[0]
        self.assertIn("F0002 [low] Second stage purpose", unknowns)
        self.assertIn("  - Recorded " + self.ledger()["findings"][1]["created_utc"], unknowns)
        self.assertEqual(json.loads((self.root / "evidence.json").read_text(encoding="utf-8")), self.ledger())
        self.assertEqual(result["case_sha256"], hashlib.sha256((self.root / "case.json").read_bytes()).hexdigest())

    def test_report_without_toolchain_or_findings(self):
        self.ingest(b"lonely")
        self.assertEqual(self.run_case("report")[0], 0)
        text = (self.root / "report.md").read_text(encoding="utf-8")
        self.assertIn("- Worker image not recorded", text)
        self.assertIn("Analysis findings remain to be recorded.", text)
        self.assertIn("No unknowns are recorded.", text)
        self.assertIn("- 0 of 1 artifacts are cited by findings", text)


class TriageTests(unittest.TestCase):
    def triage(self, data):
        return case.triage_data(data, "a" * 64, {})

    def test_strings_offsets_encodings_and_truncation(self):
        # The final "d" of the ASCII string must not start the UTF-16LE string that follows its NUL.
        data = b"\x00\x01hello world\x00" + "wide text".encode("utf-16le") + b"\x00short\x00" + b"A" * 5000
        result = self.triage(data)
        self.assertEqual([(s["offset"], s["encoding"], s["full_byte_length"]) for s in result["strings"]],
                         [(2, "ascii", 11), (14, "utf-16le", 18), (39, "ascii", 5000)])
        self.assertEqual([s["text"] for s in result["strings"][:2]], ["hello world", "wide text"])
        # A short ASCII tail is not glued on either, and a UTF-16LE run left too short after trimming is dropped.
        glued = self.triage(b"world\x00" + "widestring".encode("utf-16le") + b"\x00\x01xy\x00" + "abcde".encode("utf-16le"))
        self.assertEqual([(s["offset"], s["encoding"], s["text"]) for s in glued["strings"]],
                         [(6, "utf-16le", "widestring")])
        self.assertEqual((len(result["strings"][2]["text"]), result["strings"][2]["full_byte_length"]), (4096, 5000))
        self.assertFalse(result["strings_truncated"])
        with patch.object(case, "STRING_LIMIT", 2):
            limited = self.triage(data)
        self.assertTrue(limited["strings_truncated"])
        self.assertEqual(len(limited["strings"]), 2)

    def test_format_hints(self):
        elf = self.triage(b"\x7fELF\x02\x01\x01" + bytes(11) + b"\x3e\x00" + bytes(44))
        self.assertEqual((elf["format_hint"], elf["elf"]["machine"]), ("ELF", 62))
        self.assertEqual({key: elf["elf"][key] for key in ("e_type", "e_entry", "phnum", "shnum")},
                         dict(e_type=0, e_entry=0, phnum=0, shnum=0))
        for header in (b"\x7fELF\x01\x01\x01" + bytes(44), b"\x7fELF\x02\x01\x01" + bytes(56),
                       b"\x7fELF\x03\x01\x01" + bytes(60), b"\x7fELF\x02\x03\x01" + bytes(60)):
            self.assertEqual(set(self.triage(header)["elf"]), {"elf_class", "data_encoding", "machine"})
        pe = self.triage(b"MZ" + bytes(62))
        self.assertEqual(pe["format_hint"], "PE candidate")
        self.assertIn("pe", pe)
        thin_le = self.triage(b"\xcf\xfa\xed\xfe" + (0x0100000C).to_bytes(4, "little") + bytes(4) + (2).to_bytes(4, "little"))
        self.assertEqual(thin_le["format_hint"], "Mach-O")
        self.assertEqual(thin_le["macho"], dict(endian="little", bits=64, cputype=0x0100000C, filetype=2))
        thin_be = self.triage(b"\xfe\xed\xfa\xce" + (18).to_bytes(4, "big") + bytes(4) + (6).to_bytes(4, "big"))
        self.assertEqual(thin_be["macho"], dict(endian="big", bits=32, cputype=18, filetype=6))
        for magic in (b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            self.assertEqual(self.triage(magic + bytes(28))["format_hint"], "Mach-O")
        fat = self.triage(b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big") + bytes(40))
        self.assertEqual((fat["format_hint"], fat["macho"]), ("Mach-O universal", dict(fat_arch_count=2, fat64=False)))
        self.assertEqual(self.triage(b"\xca\xfe\xba\xbf\x00\x00\x00\x01" + bytes(32))["format_hint"], "Mach-O universal")
        java = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(4096)
        self.assertEqual(self.triage(java)["format_hint"], "unknown")
        self.assertEqual(self.triage(b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + bytes(10))["format_hint"], "unknown")
        self.assertEqual(self.triage(b"PK\x03\x04")["format_hint"], "ZIP candidate")
        self.assertEqual(self.triage(b"#!/bin/sh\n")["format_hint"], "script")
        for kind in ("Mach-O", "Mach-O universal"):
            summary = {"size": 1, "format_hint": kind, "strings_count": 0, "strings_truncated": False}
            self.assertEqual(projection.technical_summary(summary)["format_hint"], kind)


class TextTests(unittest.TestCase):
    def test_safe_text_strips_format_and_control_characters(self):
        self.assertEqual(case.safe_text("invoice‮gpj.exe"), "invoicegpj.exe")
        self.assertEqual(case.safe_text("a​b﻿c⁦d⁩"), "abcd")
        self.assertEqual(case.safe_text("x\x1b[31m\x7f\x85 y"), "x [31m   y")
        self.assertEqual(case.safe_text("café 中"), "café 中")
        self.assertEqual(case.safe_text("bad\udc80"), "bad?")

    def test_defang(self):
        cases = {
            "http://evil.example.com:8080/a.php?q=1": "hxxp://evil[.]example[.]com:8080/a.php?q=1",
            "HTTPS://Bad.Example.ORG": "hxxps://Bad[.]Example[.]ORG",
            "contact c2.example.net or update.badsite.ru.": "contact c2[.]example[.]net or update[.]badsite[.]ru.",
            "callback 192.168.10.254:443 then 8.8.8.8": "callback 192[.]168[.]10[.]254:443 then 8[.]8[.]8[.]8",
            "mail admin@evil.xyz": "mail admin@evil[.]xyz",
            "see report.md and case.py": "see report.md and case.py",
            "kernel32.dll config.json payload.exe": "kernel32.dll config.json payload.exe",
            "os.path.join and self.root": "os.path.join and self.root",
            "version 10.0.19041 and 1.2.3": "version 10.0.19041 and 1.2.3",
            "999.1.1.1 and 1.2.3.4.5": "999.1.1.1 and 1.2.3.4.5",
            "sha " + "ab" * 32: "sha " + "ab" * 32,
            "libc.so.6": "libc.so.6",
        }
        for value, expected in cases.items():
            self.assertEqual(case.defang(value), expected, value)
        self.assertEqual(case.defang(case.defang("http://a.example.com")), "hxxp://a[.]example[.]com")


if __name__ == "__main__":
    unittest.main()
