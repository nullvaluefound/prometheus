"""Hashed evidence, case-state tools through the broker, the reference check, review runs and the Forge routes."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import cli, evidence, forge, forge_api, investigation, models, review, runtime, server
from re_harness.case import atomic_json
from tests.forge_support import ForgeServer, ScriptedAdapter, write_case

DIGEST = "a" * 64
OTHER = "b" * 64
SUMMARY = {"tool": "artifact_summary", "artifact": DIGEST, "artifact_bytes": 16,
           "summary": {"size": 16, "format_hint": "ELF", "strings_count": 0, "strings_truncated": False,
                       "entry": "0x401000"}}
LEDGER = {"artifacts": {DIGEST: {}}, "findings": []}


def call(name, **arguments):
    """A model tool call as an adapter step returns it."""
    return {"id": None, "name": name, "arguments": arguments}


def ask(name, **arguments):
    """A broker call."""
    return {"name": name, "arguments": arguments}


class CaseState(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        write_case(self.state, "review", "sha256:" + DIGEST)
        self.folder = runtime.case_path(self.state, "review")
        for patcher in (patch.object(runtime, "worker", return_value=(0, json.dumps(SUMMARY).encode())),
                        patch.object(server.projection, "project", side_effect=lambda value, *args: value),
                        patch.object(forge, "case_ledger", return_value=LEDGER)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def broker(self, tools=None, audience="local"):
        allowed = set(tools) if tools is not None else set(models.local_model.ROLES["native"])
        return server.Broker(self.state, "review", allowed, audience=audience)

    def reply(self, result):
        return json.loads(result["content"][0]["text"])

    def audit(self):
        return [json.loads(line) for line in (self.folder / "audit.jsonl").read_text(encoding="ascii").splitlines()]

    def summary_evidence(self, broker=None):
        return self.reply((broker or self.broker()).call(ask("artifact_summary", artifact=DIGEST)))["evidence_id"]


class EvidenceTests(CaseState):
    def test_the_broker_keeps_what_it_released_under_its_hash(self):
        broker = self.broker()
        first = self.summary_evidence(broker)
        self.assertEqual(self.summary_evidence(broker), first)  # identical results share one file
        entry = evidence.load(self.folder, first)
        self.assertEqual((entry["tool"], entry["excerpt"], entry["reply"]), ("artifact_summary", False, SUMMARY))
        self.assertEqual(self.audit()[-1]["evidence"], first)
        self.assertEqual(len(list((self.folder / "evidence").glob("*.json"))), 1)
        self.assertEqual([row["id"] for row in evidence.listing(self.folder)], [first])

    def test_tampered_or_absent_evidence_does_not_resolve(self):
        evidence_id = self.summary_evidence()
        path = self.folder / "evidence" / f"{evidence_id}.json"
        entry = json.loads(path.read_text())
        entry["reply"]["summary"]["format_hint"] = "PE"
        path.write_text(json.dumps(entry))
        with self.assertRaisesRegex(evidence.EvidenceError, "evidence_hash_mismatch"):
            evidence.load(self.folder, evidence_id)
        self.assertEqual(evidence.missing(self.folder, ["evidence:" + evidence_id, "RVA 0x10", "evidence:" + "c" * 64]),
                         [evidence_id, "c" * 64])
        with self.assertRaises(evidence.EvidenceError):
            evidence.load(self.folder, "../x")

    def test_the_cli_refuses_a_finding_that_cites_unknown_evidence(self):
        args = argparse.Namespace(case="review", command="finding", artifact=[DIGEST], kind="observed",
                                  confidence="low", claim="x", evidence=["evidence:" + "c" * 64], supersedes=None)
        with patch.object(cli, "STATE", self.state), patch.object(cli, "call_worker") as worker:
            with self.assertRaisesRegex(runtime.RuntimeFailure, "Unknown evidence id"):
                cli.operator_action(args)
        worker.assert_not_called()


class StateToolTests(CaseState):
    def test_state_tools_get_the_broker_checks_and_audit_no_text(self):
        reviewer = self.broker(models.local_model.ROLES["review"])
        self.assertEqual(self.reply(reviewer.call(ask("add_lead", artifact=DIGEST, title="x")))["reason"],
                         "tool_outside_role")
        broker = self.broker()
        reply = self.reply(broker.call(ask("add_lead", artifact=DIGEST, address="0x00401000",
                                            title="Secret-looking title")))
        self.assertEqual(reply, {"status": "recorded", "lead": "L1"})
        events = [event for event in self.audit() if event.get("tool") == "add_lead"]
        self.assertEqual([event["decision"] for event in events], ["intercepted", "dispatched", "investigation_write"])
        self.assertNotIn("Secret-looking", (self.folder / "audit.jsonl").read_text())
        self.assertEqual(events[-1]["arguments"]["address"], "0x401000")
        self.assertIn("text_sha256", events[-1]["arguments"])
        folder = self.folder
        atomic_json(folder / "scope.json", {**runtime.read_json(folder / "scope.json"), "paused": True})
        self.assertEqual(self.reply(broker.call(ask("case_overview")))["reason"], "case_paused")
        self.assertFalse(investigation.load(self.state, "review")["observations"])

    def test_writes_need_admitted_artifacts_and_observed_needs_evidence(self):
        broker = self.broker()
        for arguments, reason in (({"artifact": OTHER, "title": "x"}, "artifact_not_admitted"),
                                  ({"artifact": DIGEST, "title": ""}, "invalid_title"),
                                  ({"artifact": DIGEST, "title": "x", "extra": 1}, "invalid_fields")):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.reply(broker.call(ask("add_lead", **arguments)))["reason"], reason)
        self.assertEqual(self.reply(broker.call(ask("record_observation", kind="observed", text="ELF",
                                                     artifact=DIGEST)))["reason"], "observed_needs_evidence")
        self.assertEqual(self.reply(broker.call(ask("record_observation", kind="observed", text="ELF",
                                                     artifact=DIGEST, evidence=["c" * 64])))["reason"],
                         "unknown_evidence")
        evidence_id = self.summary_evidence(broker)
        reply = self.reply(broker.call(ask("record_observation", kind="observed", text="An ELF.", artifact=DIGEST,
                                            evidence=[evidence_id])))
        self.assertEqual(reply, {"status": "recorded", "observation": "O1"})
        with patch.object(forge, "case_ledger", side_effect=runtime.RuntimeFailure("ledger_unavailable")):
            self.assertEqual(self.reply(self.broker().call(ask("add_lead", artifact=DIGEST, title="x")))["reason"],
                             "admission_unverified")

    def test_read_back_withholds_text_written_under_grants_not_active_now(self):
        soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat()
        grant = {"id": "g" * 32, "tool": "ghidra_decompile", "arguments": {"artifact": DIGEST, "address": "0x401000"},
                 "audience": "local", "expires_utc": soon}
        atomic_json(self.folder / "scope.json", {**runtime.read_json(self.folder / "scope.json"), "grants": [grant]})
        writer = self.broker()
        writer.released_grants.add("g" * 32)
        writer.call(ask("add_lead", artifact=DIGEST, title="Quotes the decompilation"))
        writer.call(ask("update_plan", items=["Step one"]))
        local = self.reply(self.broker().call(ask("case_overview")))
        self.assertEqual((local["leads"][0]["title"], local["plan"]), ("Quotes the decompilation", ["Step one"]))
        cloud = self.reply(self.broker(audience="mcp").call(ask("case_overview")))
        self.assertEqual((cloud["leads"][0]["title"], cloud["plan"]), (investigation.WITHHELD, [investigation.WITHHELD]))
        detail = self.reply(self.broker(audience="mcp").call(ask("lead_detail", lead="L1")))
        self.assertEqual(detail["lead"]["title"], investigation.WITHHELD)

    def test_a_proposal_is_a_checked_candidate_not_a_finding(self):
        broker = self.broker()
        evidence_id = self.summary_evidence(broker)
        reply = self.reply(broker.call(ask("propose_finding", claim=f"{DIGEST} is an ELF entering at 0x401000.",
                                            kind="observed", confidence="medium", artifacts=[DIGEST],
                                            evidence=[evidence_id], counterevidence="None found.")))
        self.assertEqual((reply["status"], reply["candidate"], reply["check"]["result"]), ("proposed", "C1", "passed"))
        bad = self.reply(broker.call(ask("propose_finding", claim="Decoder at 0x5120.", kind="observed",
                                          confidence="low", artifacts=[DIGEST], evidence=[])))
        self.assertEqual(bad["check"]["result"], "failed")
        # The model sees which of its own values failed, so it can fix the claim.
        self.assertEqual({(row["code"], row["ref"]) for row in bad["check"]["problems"]},
                         {("address_not_in_evidence", "0x5120"), ("observed_without_evidence", None)})
        again = self.reply(broker.call(ask("propose_finding", claim="Decoder at 0x5120.", kind="observed",
                                           confidence="low", artifacts=[DIGEST], evidence=[])))
        self.assertEqual(again["reason"], "duplicate_proposal")
        stored = investigation.load(self.state, "review")["candidates"]
        self.assertEqual([(row["id"], row["state"], row["finding"]) for row in stored],
                         [("C1", "proposed", None), ("C2", "proposed", None)])


class CheckTests(CaseState):
    def candidate(self, **fields):
        return {"claim": "x", "kind": "inferred", "artifacts": [DIGEST], "evidence": [], **fields}

    def test_the_check_reports_each_unresolved_reference(self):
        evidence_id = self.summary_evidence()
        admitted = lambda: {DIGEST}  # noqa: E731
        self.assertEqual(review.check(self.folder, self.candidate(), admitted)["result"], "passed")
        result = review.check(self.folder, self.candidate(
            claim=f"{OTHER} at 0x401000 and 0x10 (size 16)", artifacts=[DIGEST, OTHER],
            evidence=[evidence_id, "c" * 64]), admitted)
        self.assertEqual(result["result"], "failed")
        self.assertEqual(sorted((problem["code"], problem["ref"]) for problem in result["problems"]),
                         [("address_not_in_evidence", "0x10"), ("artifact_not_admitted", OTHER),
                          ("claim_names_unadmitted_sha256", OTHER), ("unknown_evidence", "c" * 64)])
        unreadable = review.check(self.folder, self.candidate(), lambda: (_ for _ in ()).throw(OSError("x")))
        self.assertEqual(unreadable["result"], "not_assessed")

    def test_the_gate_wants_an_open_question_with_admitted_artifacts_and_an_outcome(self):
        investigation.add_question(self.state, "review", "Is it packed?", "", [DIGEST], "analyst")
        investigation.add_question(self.state, "review", "C2?", "A C2 list", [OTHER], "analyst")
        data = investigation.load(self.state, "review")
        self.assertEqual(investigation.gate(data, {DIGEST})[0], [])
        investigation.add_question(self.state, "review", "Config?", "Decoded config", [DIGEST], "analyst")
        usable, reason = investigation.gate(investigation.load(self.state, "review"), {DIGEST})
        self.assertEqual(([row["id"] for row in usable], reason), (["Q3"], None))


class ReviewFixTests(CaseState):
    """The second review's findings: grant taint on read-back, excerpt evidence, recording races, address checks."""

    def grant(self, audience="local", grant_id="g" * 32, address="0x401000"):
        soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat()
        scope = runtime.read_json(self.folder / "scope.json")
        scope["grants"] = [row for row in scope["grants"] if row["id"] != grant_id] + [{
            "id": grant_id, "tool": "ghidra_decompile", "arguments": {"artifact": DIGEST, "address": address},
            "audience": audience, "expires_utc": soon}]
        atomic_json(self.folder / "scope.json", scope)

    def revoke(self, grant_id="g" * 32):
        scope = runtime.read_json(self.folder / "scope.json")
        scope["grants"] = [row for row in scope["grants"] if row["id"] != grant_id]
        atomic_json(self.folder / "scope.json", scope)

    def decompiled(self, broker):
        excerpt = {"tool": "ghidra_decompile", "artifact": DIGEST, "artifact_bytes": 16,
                   "summary": {"provider_response": "structured", "top_level_fields": 1},
                   "evidence_excerpt": {"text": "key = 0x5a; port = 0x1bb;"}}
        with patch.object(runtime, "worker", return_value=(0, json.dumps(excerpt).encode())):
            return self.reply(broker.call(ask("ghidra_decompile", artifact=DIGEST, address="0x401000")))

    def test_text_shown_by_a_read_taints_what_the_reader_writes(self):
        self.grant()
        writer = self.broker()
        writer.released_grants.add("g" * 32)
        writer.call(ask("add_lead", artifact=DIGEST, title="DECOMPILED: xor key 0x5a"))
        reader = self.broker()
        self.assertEqual(self.reply(reader.call(ask("case_overview")))["leads"][0]["title"], "DECOMPILED: xor key 0x5a")
        reader.call(ask("add_lead", artifact=DIGEST, title="copy of the key"))
        leads = investigation.load(self.state, "review")["leads"]
        self.assertEqual([row["grants"] for row in leads], [["g" * 32], ["g" * 32]])
        self.revoke()
        cloud = self.reply(self.broker(audience="mcp").call(ask("case_overview")))
        self.assertEqual([row["title"] for row in cloud["leads"]], [investigation.WITHHELD] * 2)

    def test_a_chat_answer_after_a_read_carries_the_grants_it_saw(self):
        self.grant()
        writer = self.broker()
        writer.released_grants.add("g" * 32)
        writer.call(ask("add_lead", artifact=DIGEST, title="Quotes an excerpt"))
        with patch.dict(models.ADAPTERS, {"ollama": ScriptedAdapter}):
            ScriptedAdapter.script = [("", [call("case_overview")]), ("Summary.", [])]
            rows = models.converse(self.state, "review", ReviewRunTests.CONFIG,
                                   {"role": "native", "tools": ["case_overview"], "allow_cloud": False}, [], "go",
                                   "analyst")
        self.assertEqual(rows[-1]["grants"], ["g" * 32])

    def test_excerpt_evidence_counts_only_for_sessions_holding_its_grants(self):
        self.grant()
        local = self.broker()
        evidence_id = self.decompiled(local)["evidence_id"]
        self.assertTrue(evidence.load(self.folder, evidence_id)["excerpt"])
        cloud = self.broker(audience="mcp")
        guess = "Key at 0x5a, 0x1bb, 0x22, 0x33."
        for name, arguments in (("propose_finding", {"claim": guess, "kind": "observed", "confidence": "low",
                                                     "artifacts": [DIGEST], "evidence": [evidence_id]}),
                                ("record_observation", {"kind": "observed", "text": guess, "artifact": DIGEST,
                                                        "evidence": [evidence_id]})):
            with self.subTest(name=name):
                self.assertEqual(self.reply(cloud.call(ask(name, **arguments)))["reason"], "evidence_not_granted")
        reply = self.reply(local.call(ask("propose_finding", claim="Key 0x5a and port 0x1bb.", kind="observed",
                                          confidence="medium", artifacts=[DIGEST], evidence=[evidence_id])))
        self.assertEqual(reply["check"]["result"], "passed")
        self.assertEqual(investigation.load(self.state, "review")["candidates"][0]["grants"], ["g" * 32])
        self.revoke()
        self.assertEqual(self.reply(self.broker().call(ask("record_observation", kind="observed", text="x",
                                                           artifact=DIGEST, evidence=[evidence_id])))["reason"],
                         "evidence_not_granted")

    def test_the_same_reply_to_two_audiences_is_two_releases(self):
        local = self.summary_evidence(self.broker())
        cloud = self.summary_evidence(self.broker(audience="mcp"))
        self.assertNotEqual(local, cloud)
        self.assertEqual([evidence.load(self.folder, item)["audience"] for item in (local, cloud)], ["local", "mcp"])

    def test_addresses_must_be_shown_by_address_fields_or_labels(self):
        evidence_id = self.summary_evidence()
        admitted = lambda: {DIGEST}  # noqa: E731
        candidate = {"kind": "inferred", "artifacts": [DIGEST], "evidence": [evidence_id]}
        for claim, passes in (("Entry at 0x401000.", True), ("Config at 0x0 then 0x10.", False),
                              ("Decoder FUN_00405a10 runs first.", False), ("Entry FUN_00401000.", True)):
            with self.subTest(claim=claim):
                result = review.check(self.folder, {**candidate, "claim": claim}, admitted)
                self.assertEqual(result["result"], "passed" if passes else "failed")
        self.grant()
        decompile = self.decompiled(self.broker())["evidence_id"]
        result = review.check(self.folder, {**candidate, "evidence": [decompile], "claim": "Function 0x401000."},
                              admitted)
        self.assertEqual(result["result"], "passed")

    def test_a_write_is_audited_as_written_even_if_the_case_pauses_after_it(self):
        real = investigation.apply

        def pausing(*args):
            result = real(*args)
            atomic_json(self.folder / "scope.json", {**runtime.read_json(self.folder / "scope.json"), "paused": True})
            return result
        with patch.object(investigation, "apply", side_effect=pausing):
            reply = self.reply(self.broker().call(ask("add_lead", artifact=DIGEST, title="x")))
        self.assertEqual(reply["status"], "recorded")
        self.assertEqual(self.audit()[-1]["decision"], "investigation_write")

    def test_a_lock_is_removed_only_by_its_holder_or_when_stale(self):
        path = investigation.store_path(self.state, "review").with_suffix(".lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("someone-else", encoding="ascii")
        with patch.object(investigation.time, "monotonic", side_effect=[0, 0, 10]), patch.object(
                investigation.time, "sleep"):
            with self.assertRaisesRegex(investigation.InvestigationError, "investigation_busy"):
                with investigation.locked(self.state, "review"):
                    pass
        self.assertEqual(path.read_text(encoding="ascii"), "someone-else")
        os.utime(path, (0, 0))
        with investigation.locked(self.state, "review"):
            self.assertNotEqual(path.read_text(encoding="ascii"), "someone-else")
        self.assertFalse(path.exists())

    def test_claiming_a_candidate_blocks_a_second_record_or_a_reject(self):
        self.broker().call(ask("propose_finding", claim="An ELF.", kind="inferred", confidence="low",
                               artifacts=[DIGEST], evidence=[]))
        investigation.claim_candidate(self.state, "review", "C1", "analyst")
        for action in (lambda: investigation.claim_candidate(self.state, "review", "C1", "other"),
                       lambda: investigation.decide_candidate(self.state, "review", "C1", "rejected", "other")):
            with self.assertRaisesRegex(investigation.InvestigationError, "candidate_already_decided"):
                action()
        investigation.release_candidate(self.state, "review", "C1")
        self.assertEqual(investigation.load(self.state, "review")["candidates"][0]["state"], "proposed")


class DerivedFieldTests(CaseState):
    """The broker adds arithmetic a small model gets wrong: entry VA, its section, ELF entry in hex."""

    def summarize(self, summary):
        reply = {"tool": "artifact_summary", "artifact": DIGEST, "artifact_bytes": 16, "summary": summary}
        with patch.object(runtime, "worker", return_value=(0, json.dumps(reply).encode())):
            return self.reply(self.broker().call(ask("artifact_summary", artifact=DIGEST)))

    def test_pe_entry_va_and_section(self):
        sections = [{"rva": "0x1000", "raw_offset": 512, "raw_size": 512, "virtual_size": 4096, "flags": "0x60000020",
                     "entropy": 5.1},
                    {"rva": "0x3000", "raw_offset": 1024, "raw_size": 0, "virtual_size": 8192, "flags": "0xe0000020",
                     "entropy": 0.0}]
        pe = {"parsed": True, "sections_count": 2, "import_libraries_count": 1, "certificate_bytes": 0,
              "machine": "0x14c", "entry_rva": "0x3010", "image_base": "0x400000", "overlay_offset": None,
              "sections": sections}
        reply = self.summarize({"size": 16, "format_hint": "PE candidate", "strings_count": 0,
                                "strings_truncated": False, "pe": pe})
        self.assertEqual(reply["derived"], {"entry_va": "0x403010", "entry_section": 1})
        self.assertEqual(evidence.load(self.folder, reply["evidence_id"])["reply"]["derived"]["entry_va"], "0x403010")
        claim = self.reply(self.broker().call(ask("propose_finding", claim="Entry point VA 0x403010.", kind="observed",
                                                  confidence="high", artifacts=[DIGEST],
                                                  evidence=[reply["evidence_id"]])))
        self.assertEqual(claim["check"]["result"], "passed")

    def test_no_section_index_when_sections_are_missing_and_va_wraps_like_the_loader(self):
        sections = [{"rva": "0x1000", "raw_offset": 512, "raw_size": 512, "virtual_size": 4096, "flags": "0x60000020",
                     "entropy": 5.1}]
        pe = {"parsed": True, "sections_count": 200, "import_libraries_count": 1, "certificate_bytes": 0,
              "machine": "0x14c", "entry_rva": "0x20000", "image_base": "0xffff0000", "overlay_offset": None,
              "sections": sections}
        reply = self.summarize({"size": 16, "format_hint": "PE candidate", "strings_count": 0,
                                "strings_truncated": False, "pe": pe})
        # The entry may be in one of the 199 sections not listed, so no index; a 32-bit VA wraps at 2**32.
        self.assertEqual(reply["derived"], {"entry_va": "0x10000"})

    def test_elf_entry_in_hex(self):
        reply = self.summarize({"size": 16, "format_hint": "ELF", "strings_count": 0, "strings_truncated": False,
                                "elf": {"elf_class": 2, "data_encoding": 1, "machine": 62, "e_type": 3,
                                        "e_entry": 4160, "phnum": 13, "shnum": 31}})
        self.assertEqual(reply["derived"], {"e_entry_hex": "0x1040"})


class FactRuleTests(ReviewFixTests):
    """ARTEX's fact methodology: facts are held to their evidence, carry a source, and findings rest on facts."""

    def sample_evidence(self):
        """An import-names reply: content the sample's author controls, released under grant g."""
        self.grant()
        scope = runtime.read_json(self.folder / "scope.json")
        scope["grants"][0].update(tool="artifact_imports", arguments={"artifact": DIGEST, "offset": 0, "limit": 20})
        atomic_json(self.folder / "scope.json", scope)
        reply = {"tool": "artifact_imports", "artifact": DIGEST, "artifact_bytes": 16,
                 "summary": {"rows": [{"kind": "pe_import", "name": "ExitProcess", "address": "0x2040"}]}}
        return evidence.record(self.folder, "artifact_imports", {"artifact": DIGEST, "offset": 0, "limit": 20}, reply,
                               True, "local", ["g" * 32], "t" * 32, "s" * 32)

    def test_an_observed_fact_is_held_to_its_evidence(self):
        summary = self.summary_evidence()
        broker = self.broker()
        refused = self.reply(broker.call(ask("record_observation", kind="observed", text="Decoder at 0x5120.",
                                             artifact=DIGEST, evidence=[summary])))
        self.assertEqual(refused["reason"], "address_not_in_evidence")
        self.assertIn("guidance", json.loads(models.boundary.for_model(json.dumps(refused), True)))
        inferred = self.reply(broker.call(ask("record_observation", kind="inferred", text="Decoder at 0x5120?",
                                              artifact=DIGEST, evidence=[summary])))
        self.assertEqual(inferred["status"], "recorded")
        self.reply(broker.call(ask("record_observation", kind="observed", text="Entry point 0x401000.",
                                   artifact=DIGEST, evidence=[summary])))
        rows = investigation.load(self.state, "review")["observations"]
        self.assertEqual([(row["kind"], row["sources"]) for row in rows],
                         [("inferred", ["tool_output"]), ("observed", ["tool_output"])])
        guessed = self.reply(broker.call(ask("record_observation", kind="inferred", text="Probably packed.",
                                             artifact=DIGEST)))
        self.assertEqual(guessed["status"], "recorded")
        self.assertEqual(investigation.load(self.state, "review")["observations"][-1]["sources"], ["inference"])

    def test_sources_come_from_the_tool_not_the_model(self):
        names = self.sample_evidence()
        broker = self.broker()
        broker.released_grants.add("g" * 32)
        self.reply(broker.call(ask("record_observation", kind="observed", text="Imports ExitProcess at 0x2040.",
                                   artifact=DIGEST, evidence=[names])))
        self.assertEqual(investigation.load(self.state, "review")["observations"][0]["sources"], ["sample_content"])

    def test_findings_can_rest_on_observations(self):
        summary = self.summary_evidence()
        broker = self.broker()
        broker.call(ask("record_observation", kind="observed", text="Entry point 0x401000.", artifact=DIGEST,
                        evidence=[summary]))
        reply = self.reply(broker.call(ask("propose_finding", claim="The entry point is 0x401000.", kind="observed",
                                           confidence="high", artifacts=[DIGEST], observations=["O1"])))
        self.assertEqual(reply["check"]["result"], "passed")
        candidate = investigation.load(self.state, "review")["candidates"][0]
        self.assertEqual((candidate["observations"], candidate["evidence"], candidate["check"]["sources"]),
                         (["O1"], [summary], ["tool_output"]))
        self.assertEqual(self.reply(broker.call(ask("propose_finding", claim="x", kind="inferred", confidence="low",
                                                    artifacts=[DIGEST], observations=["O9"])))["reason"],
                         "unknown_observation")

    def test_an_answer_needs_a_tool_s_own_result_not_only_sample_content(self):
        names = self.sample_evidence()
        question = investigation.add_question(self.state, "review", "Imports?", "Names", [DIGEST], "analyst")["id"]

        def seed(data):
            data["run"] = {"id": "R1", "state": "running", "questions": [question]}
            data["candidates"] += [
                {"id": "C1", "state": "proposed", "artifacts": [DIGEST], "evidence": [names],
                 "check": {"result": "passed", "problems": [], "sources": ["sample_content"]}},
                {"id": "C2", "state": "proposed", "artifacts": [DIGEST], "evidence": [self.summary_evidence()],
                 "check": {"result": "passed", "problems": []}}]  # older proposal: no sources recorded
        investigation.update(self.state, "review", seed)
        with self.assertRaisesRegex(investigation.InvestigationError, "answer_needs_tool_output"):
            investigation.propose_answer(self.state, "review", "R1", question, ["C1"], {})
        answered = investigation.propose_answer(self.state, "review", "R1", question, ["C1", "C2"], {})
        self.assertEqual(answered["state"], "answer_proposed")


class FactRuleReviewTests(FactRuleTests):
    """The third review's findings on the fact rules."""

    def run_question(self):
        question = investigation.add_question(self.state, "review", "Imports?", "Names", [DIGEST], "analyst")["id"]

        def seed(data):
            data["run"] = {"id": "R1", "state": "running", "questions": [question]}
        investigation.update(self.state, "review", seed)
        return question

    def propose(self, broker, claim, kind="observed", **fields):
        return self.reply(broker.call(ask("propose_finding", claim=claim, kind=kind, confidence="high",
                                          artifacts=[DIGEST], **fields)))

    def test_a_proposal_with_new_evidence_is_not_a_duplicate(self):
        summary = self.summary_evidence()
        broker = self.broker()
        failed = self.propose(broker, "Entry point 0x401000.")
        self.assertEqual({problem["code"] for problem in failed["check"]["problems"]},
                         {"address_not_in_evidence", "observed_without_evidence"})
        fixed = self.propose(broker, "Entry point 0x401000.", evidence=[summary])
        self.assertEqual(fixed["check"]["result"], "passed")
        self.assertEqual(self.propose(broker, "Entry point 0x401000.", evidence=[summary])["reason"],
                         "duplicate_proposal")
        self.assertEqual(self.propose(broker, "Entry point 0x401000.", "inferred", evidence=[summary])["status"],
                         "proposed")

    def test_a_finding_rests_on_no_more_evidence_than_a_recorded_finding_keeps(self):
        self.assertEqual(investigation.MAX_FINDING_EVIDENCE, cli.MAX_EVIDENCE)
        ids = [evidence.record(self.folder, "artifact_summary", {"artifact": DIGEST}, {"page": index}, False,
                               "local", [], "t" * 32, "s" * 32) for index in range(17)]
        broker = self.broker()
        broker.call(ask("record_observation", kind="inferred", text="Page sixteen.", artifact=DIGEST,
                        evidence=ids[16:]))
        refused = self.propose(broker, "Seventeen pages.", "inferred", evidence=ids[:16], observations=["O1"])
        self.assertEqual(refused["reason"], "too_much_evidence")
        self.assertEqual(self.propose(broker, "Sixteen pages.", "inferred", evidence=ids[:16])["status"], "proposed")

    def test_evidence_about_another_artifact_shows_nothing(self):
        other = evidence.record(self.folder, "artifact_summary", {"artifact": OTHER}, {"entry": "0x401000"}, False,
                                "local", [], "t" * 32, "s" * 32)
        broker = self.broker()
        refused = self.reply(broker.call(ask("record_observation", kind="observed", text="Entry point 0x401000.",
                                             artifact=DIGEST, evidence=[other])))
        self.assertEqual(refused["reason"], "evidence_other_artifact")
        reply = self.propose(broker, "Entry point 0x401000.", evidence=[other])
        self.assertEqual([problem["code"] for problem in reply["check"]["problems"]],
                         ["evidence_other_artifact", "address_not_in_evidence"])

    def test_granted_text_is_sample_content_whatever_the_tool(self):
        self.assertEqual([review.source_of({"tool": tool, "excerpt": excerpt}) for tool, excerpt in (
            ("ghidra_functions", True), ("ghidra_decompile", True), ("artifact_strings", True),
            ("ghidra_functions", False), ("ghidra_xrefs", False), ("capa_triage", False))],
            ["sample_content"] * 3 + ["tool_output"] * 3)

    def test_an_address_only_sample_content_shows_does_not_ground_an_answer(self):
        names, summary = self.sample_evidence(), self.summary_evidence()
        question = self.run_question()
        broker = self.broker()
        broker.released_grants.add("g" * 32)
        imported = self.propose(broker, "Imports ExitProcess at 0x2040.", evidence=[names, summary])
        entry = self.propose(broker, "Entry point 0x401000; imports ExitProcess.", evidence=[names, summary])
        rows = {row["id"]: row["check"] for row in investigation.load(self.state, "review")["candidates"]}
        self.assertEqual([(rows[reply["candidate"]]["result"], rows[reply["candidate"]]["grounded"])
                          for reply in (imported, entry)], [("passed", False), ("passed", True)])
        with self.assertRaisesRegex(investigation.InvestigationError, "answer_needs_tool_output"):
            investigation.propose_answer(self.state, "review", "R1", question, [imported["candidate"]], {})
        answered = investigation.propose_answer(self.state, "review", "R1", question,
                                                [imported["candidate"], entry["candidate"]], {})
        self.assertEqual(answered["state"], "answer_proposed")

    def test_the_audit_keeps_what_a_proposal_rests_on(self):
        summary = self.summary_evidence()
        broker = self.broker()
        broker.call(ask("record_observation", kind="observed", text="Entry point 0x401000.", artifact=DIGEST,
                        evidence=[summary]))
        self.propose(broker, "The entry point is 0x401000.", observations=["O1"])
        written = [event for event in self.audit()
                   if event["decision"] == "investigation_write" and event["tool"] == "propose_finding"]
        self.assertEqual((written[0]["arguments"]["observations"], written[0]["cited_evidence"]), (["O1"], [summary]))


class ReviewRunTests(CaseState):
    CONFIG = {"provider": "ollama", "base_url": "http://127.0.0.1:11434", "model": "lab"}

    def setUp(self):
        super().setUp()
        patcher = patch.dict(models.ADAPTERS, {"ollama": ScriptedAdapter})
        patcher.start()
        self.addCleanup(patcher.stop)
        broker = self.broker()
        self.evidence_id = self.summary_evidence(broker)
        broker.call(ask("propose_finding", claim="An ELF.", kind="observed", confidence="low", artifacts=[DIGEST],
                         evidence=[self.evidence_id]))

    def test_one_verdict_is_recorded_against_the_candidate(self):
        ScriptedAdapter.script = [("", [call("artifact_summary", artifact=DIGEST)]),
                                  ("", [call("submit_verdict", verdict="supported", rationale="Header says ELF; a "
                                                                                              "packed PE would not.")])]
        record = review.run(self.state, "review", self.CONFIG, {"allow_cloud": False}, "C1", "analyst")
        self.assertEqual(record["verdict"], "supported")
        self.assertIn("Review contract", ScriptedAdapter.last.system)
        self.assertIn("submit_verdict", [name for name, _, _ in ScriptedAdapter.last.tools])
        self.assertNotIn("add_lead", [name for name, _, _ in ScriptedAdapter.last.tools])
        stored = investigation.load(self.state, "review")["candidates"][0]
        self.assertEqual((stored["state"], [row["verdict"] for row in stored["verdicts"]]), ("proposed", ["supported"]))
        self.assertIn("review_completed", [event["decision"] for event in self.audit()])

    def test_no_verdict_is_an_error_and_records_nothing(self):
        ScriptedAdapter.script = [("I think so.", [])] * models.MAX_TURNS
        with self.assertRaises(models.ModelError):
            review.run(self.state, "review", self.CONFIG, {"allow_cloud": False}, "C1", "analyst")
        self.assertEqual(investigation.load(self.state, "review")["candidates"][0]["verdicts"], [])

    def test_a_cloud_reviewer_cannot_see_a_claim_built_on_local_grants(self):
        def change(data):
            data["candidates"][0]["grants"] = ["g" * 32]
        investigation.update(self.state, "review", change)
        cloud = {"provider": "ollama", "base_url": "https://llm.example.com", "model": "hosted"}
        with self.assertRaisesRegex(models.ModelError, "not active"):
            review.run(self.state, "review", cloud, {"allow_cloud": True}, "C1", "analyst")


class SplitTests(unittest.TestCase):
    def test_sub_questions_are_parsed_from_tool_free_json(self):
        with patch.dict(models.ADAPTERS, {"ollama": ScriptedAdapter}):
            ScriptedAdapter.script = [('Sure: {"questions": [{"text": "Is the config XOR-encoded?", "outcome": '
                                       '"A decode loop"}, {"text": ""}, "x"]}', [])]
            found = models.split_question({"provider": "ollama"}, {"text": "What is the config?", "outcome": "C2"})
        self.assertEqual(found, [("Is the config XOR-encoded?", "A decode loop")])
        self.assertEqual(ScriptedAdapter.last.finals, [True])
        self.assertEqual(ScriptedAdapter.last.tools, [])
        with patch.dict(models.ADAPTERS, {"ollama": ScriptedAdapter}), self.assertRaises(models.ModelError):
            ScriptedAdapter.script = [("no json", [])]
            models.split_question({"provider": "ollama"}, {"text": "x"})


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class InvestigationApiTests(ForgeServer, unittest.TestCase):
    def setUp(self):
        self.start_forge()
        patcher = patch.object(forge, "case_ledger", return_value={"artifacts": {self.digest: {}}, "findings": []})
        patcher.start()
        self.addCleanup(patcher.stop)

    def propose(self):
        with patch.object(runtime, "worker", return_value=(0, json.dumps(SUMMARY).encode())), \
                patch.object(server.projection, "project", side_effect=lambda value, *args: value):
            broker = server.Broker(self.state, "review", set(models.local_model.ROLES["native"]), audience="local")
            evidence_id = json.loads(broker.call(ask("artifact_summary", artifact=self.digest))["content"][0]["text"])[
                "evidence_id"]
            broker.call(ask("propose_finding", claim="An ELF.", kind="observed", confidence="low",
                             artifacts=[self.digest], evidence=[evidence_id]))
        return evidence_id

    def test_questions_are_operator_text_on_admitted_artifacts(self):
        for bad in ({"text": "", "outcome": "x"}, {"text": "x", "outcome": "x", "artifacts": [OTHER]},
                    {"text": "x", "outcome": "x", "artifacts": ["nope"]}):
            with self.subTest(bad=bad):
                self.assertEqual(self.api("POST", "cases/review/questions", bad)[0], 400)
        status, question = self.api("POST", "cases/review/questions",
                                    {"text": "Does it decode a config?", "outcome": "A config", "artifacts": [self.digest]})
        self.assertEqual((status, question["id"], question["state"]), (200, "Q1", "open"))
        self.assertEqual(self.api("PUT", "cases/review/questions/Q1", {"text": "Edited", "outcome": "A config",
                                                                      "artifacts": []})[1]["text"], "Edited")
        self.assertEqual(self.api("POST", "cases/review/questions/Q1/state", {"state": "closed"})[1]["state"], "closed")
        self.assertEqual(self.api("PUT", "cases/review/questions/Q1", {"text": "x", "outcome": ""})[1]["error"],
                         "question_closed")
        self.assertEqual(self.api("POST", "cases/review/questions/Q9/state", {"state": "open"})[0], 404)
        self.assertEqual(self.api("GET", "cases/review/investigation")[1]["questions"][0]["state"], "closed")
        decisions = [json.loads(line) for line in (runtime.case_path(self.state, "review") / "audit.jsonl")
                     .read_text().splitlines()]
        self.assertNotIn("Edited", json.dumps(decisions))
        self.assertEqual({event["operation"] for event in decisions if event["decision"] == "investigation_write"},
                         {"question", "question_closed"})

    def test_split_proposals_wait_for_the_operator(self):
        self.api("POST", "models", {"id": "lab", "name": "Lab", "provider": "ollama",
                                    "base_url": "http://127.0.0.1:11434", "model": "qwen3:32b"})
        self.api("PUT", "cases/review/settings", {"model": "lab", "allow_cloud": False, "role": "evidence",
                                                 "tools": ["artifact_summary"]})
        self.api("POST", "cases/review/questions", {"text": "What is the config?", "outcome": "C2 list",
                                                    "artifacts": [self.digest]})
        with patch.object(models, "split_question", return_value=[("Is it XOR?", "A loop"), ("Where?", "An address")]):
            task = self.wait(self.api("POST", "cases/review/questions/Q1/split")[1]["task"])
        self.assertEqual(task["result"], {"proposed": ["Q2", "Q3"]})
        questions = self.api("GET", "cases/review/investigation")[1]["questions"]
        self.assertEqual([(row["id"], row["state"], row.get("author")) for row in questions],
                         [("Q1", "open", None), ("Q2", "proposed", "model"), ("Q3", "proposed", "model")])
        self.assertEqual({item["kind"] for item in self.api("GET", "overview")[1]["waiting"]["items"]},
                         {"question_proposed"})
        accepted = self.api("POST", "cases/review/questions/Q2/state", {"state": "open"})[1]
        self.assertEqual((accepted["state"], accepted.get("author"), accepted["accepted_by"]), ("open", None, "analyst"))

    def test_candidates_are_recorded_or_rejected_only_by_the_operator(self):
        evidence_id = self.propose()
        status, entry = self.api("GET", f"cases/review/evidence/{evidence_id}")
        self.assertEqual((status, entry["reply"]["summary"]["format_hint"]), (200, "ELF"))
        self.assertEqual(self.api("GET", "cases/review/evidence/" + "c" * 64)[0], 404)
        self.assertEqual(self.api("GET", "cases/review/evidence")[1]["evidence"][0]["id"], evidence_id)
        waiting = self.api("GET", "overview")[1]["waiting"]["items"]
        self.assertEqual([(item["kind"], item["check"]) for item in waiting], [("candidate", "passed")])
        self.assertEqual(self.api("POST", "cases/review/candidates/C1/check")[1]["check"]["result"], "passed")
        seen = {}

        def finding(args):
            seen.update(vars(args))
            print(json.dumps({"id": "F0001"}))
        with patch.object(forge_api.cli, "operator_action", side_effect=finding):
            task = self.wait(self.api("POST", "cases/review/candidates/C1/record",
                                      {"claim": "An ELF, edited by the analyst.", "confidence": "high"})[1]["task"])
        self.assertEqual(task["result"], {"candidate": "C1", "finding": "F0001"})
        self.assertEqual((seen["command"], seen["claim"], seen["confidence"], seen["evidence"]),
                         ("finding", "An ELF, edited by the analyst.", "high", ["evidence:" + evidence_id]))
        candidate = self.api("GET", "cases/review/investigation")[1]["candidates"][0]
        self.assertEqual((candidate["state"], candidate["finding"], candidate["decided_by"]),
                         ("recorded", "F0001", "analyst"))
        self.assertEqual(self.api("POST", "cases/review/candidates/C1/reject", {})[1]["error"],
                         "candidate_already_decided")
        self.assertEqual(self.api("POST", "cases/review/candidates/C9/reject", {})[0], 404)

    def test_a_second_record_is_refused_while_the_first_is_queued(self):
        self.propose()
        release = __import__("threading").Event()
        blocker = self.app.tasks.submit("report", "review", "slow", "analyst", lambda: release.wait(5) and {})
        writes = []

        def finding(args):
            writes.append(args.claim)
            print(json.dumps({"id": "F000" + str(len(writes))}))
        with patch.object(forge_api.cli, "operator_action", side_effect=finding):
            first = self.api("POST", "cases/review/candidates/C1/record", {"claim": "first"})
            second = self.api("POST", "cases/review/candidates/C1/record", {"claim": "second"})
            rejected = self.api("POST", "cases/review/candidates/C1/reject", {})
            release.set()
            self.wait(blocker)
            self.wait(first[1]["task"])
        self.assertEqual((first[0], second[1]["error"], rejected[1]["error"]),
                         (202, "candidate_already_decided", "candidate_already_decided"))
        self.assertEqual(writes, ["first"])

    def test_a_failed_record_returns_the_candidate_to_proposed(self):
        self.propose()
        with patch.object(forge_api.cli, "operator_action", side_effect=runtime.RuntimeFailure("worker down")):
            task = self.wait(self.api("POST", "cases/review/candidates/C1/record", {})[1]["task"])
        self.assertEqual(task["state"], "failed")
        self.assertEqual(self.api("GET", "cases/review/investigation")[1]["candidates"][0]["state"], "proposed")

    def test_an_unreadable_store_is_unavailable_not_a_bad_request(self):
        path = investigation.store_path(self.state, "review")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="ascii")
        for method, route in (("GET", "cases/review/investigation"), ("POST", "cases/review/candidates/C1/reject")):
            with self.subTest(route=route):
                self.assertEqual(self.api(method, route, {} if method == "POST" else None)[0], 503)

    def test_review_runs_as_a_task(self):
        self.propose()
        self.assertEqual(self.api("POST", "cases/review/candidates/C1/review")[1]["error"], "no_model")
        self.api("POST", "models", {"id": "lab", "name": "Lab", "provider": "ollama",
                                    "base_url": "http://127.0.0.1:11434", "model": "qwen3:32b"})
        self.api("PUT", "cases/review/settings", {"model": "lab", "allow_cloud": False, "role": "evidence",
                                                 "tools": ["artifact_summary"]})
        with patch.object(forge_api.review, "run", return_value={"verdict": "insufficient"}) as run:
            task = self.wait(self.api("POST", "cases/review/candidates/C1/review")[1]["task"])
        self.assertEqual((task["kind"], task["result"]), ("review", {"candidate": "C1", "verdict": "insufficient"}))
        self.assertEqual(run.call_args.args[4], "C1")
        self.assertIn("case_overview", {tool["name"] for tool in self.api("GET", "policy")[1]["state_tools"]})


if __name__ == "__main__":
    unittest.main()
