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
        self.assertEqual({problem["code"] for problem in bad["check"]["problems"]},
                         {"address_not_in_evidence", "observed_without_evidence"})
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
                         [("artifact_not_admitted", OTHER), ("claim_names_unadmitted_sha256", OTHER),
                          ("unknown_evidence", "c" * 64)])
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
